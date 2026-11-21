"""Check protected startup and C's existing HTTP/CLI boundaries, without editing A/B/D."""

from dataclasses import asdict, replace
import json
import sys
from time import time

from fastapi.testclient import TestClient
import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evaluation.fixtures import Lab
from evaluation.state_evaluator import snapshot, state_matches
from role_b.approval import FabricClient
from trusted_release.crypto import canonical_json
from trusted_release.dify_api import create_retrieval_app
from trusted_release.handoff import open_store
from trusted_release.manage import main as manage
from trusted_release.protocol import TrustError, sign_release, sign_revocation
from trusted_release.rag import ChunkCandidate
from trusted_release.role_a import ExecutorReleaseCheck
from trusted_release.tests.test_handoff import TOOL, c_app, publisher


@pytest.fixture
def protected(publisher, monkeypatch):
    store, trust, key, publish = publisher
    reader = trust.with_name("fabric-reader.json")
    reader.write_text(json.dumps({"channel": "roleb", "chaincode": "edgeguard",
                                 "identity": {}, "peers": [{}, {}]}), encoding="utf-8")
    config = json.loads(trust.read_text(encoding="utf-8"))
    config["checkpoint"] = {"provider": "fabric", "config": reader.name, "max_read_seconds": 15}
    trust.write_text(json.dumps(config), encoding="utf-8")
    records, calls = {}, []
    def submit(client, transaction, *args):
        assert client.config == reader.resolve()
        calls.append((transaction, args))
        if transaction == "ReadRelease":
            value = records.get(tuple(args))
            if isinstance(value, Exception):
                raise value
        else:
            ref = json.loads(args[0])
            value = {**ref, "revoked": transaction == "RevokeRelease"}
            records[(ref["scope"], ref["kind"], ref["artifact_id"])] = value
        return {"transaction_id": "a" * 64, "block": "20", "value": value}
    monkeypatch.setattr(FabricClient, "submit", submit)
    monkeypatch.setenv("ROLE_C_REQUIRE_CHECKPOINT", "1")
    def anchor(ref, **changes):
        records[(ref.scope, ref.kind, ref.artifact_id)] = {**asdict(ref), "revoked": False, **changes}
    return store, trust, key, publish, reader, records, calls, anchor


def test_open_store_installs_checkpoint_for_every_consumer(protected):
    _, trust, _, publish, _, _, calls, anchor = protected
    ref = publish("policy", "policy", 1, {"area": "visitor_area"})
    anchor(ref)
    assert open_store(trust).load("policy", "policy").ref == ref
    assert calls == [("ReadRelease", ("campus", "policy", "policy"))]
    anchor(ref, revoked=True)
    with pytest.raises(TrustError, match="CHECKPOINT_MISMATCH"):
        open_store(trust).load("policy", "policy")


@pytest.mark.parametrize("value", [None, {}, {"provider": "typo", "config": "fabric-reader.json"},
    {"provider": "fabric", "config": ""}, {"provider": "fabric", "config": "fabric-reader.json", "optional": True},
    {"provider": "fabric", "config": "fabric-reader.json", "max_read_seconds": True}])
def test_invalid_checkpoint_config_never_disables_checks(protected, value):
    _, trust, *_ = protected
    config = json.loads(trust.read_text(encoding="utf-8"))
    config["checkpoint"] = value
    trust.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises((ValueError, TypeError)):
        open_store(trust)


def test_required_mode_cannot_fall_back_to_legacy_config(publisher, monkeypatch):
    _, trust, *_ = publisher
    monkeypatch.setenv("ROLE_C_REQUIRE_CHECKPOINT", "1")
    with pytest.raises(ValueError, match="checkpoint"):
        open_store(trust)
    monkeypatch.setenv("ROLE_C_REQUIRE_CHECKPOINT", "typo")
    with pytest.raises(ValueError, match="ROLE_C_REQUIRE_CHECKPOINT"):
        open_store(trust)


class Index:
    supports_scores = True
    def __init__(self, refs):
        self.refs = refs
    def search(self, query, limit):
        return tuple(ChunkCandidate(r.scope, r.artifact_id, r.tag, "entrance", "访客从东门进入。", 0.9)
                     for r in self.refs)[:limit]


BODY = {"knowledge_id": "campus", "query": "入口",
        "retrieval_setting": {"top_k": 2, "score_threshold": 0.0}}
HEADERS = {"Authorization": "Bearer fixture-checkpoint-retrieval-key"}


def test_retrieval_dependency_failure_discards_already_verified_partial_hits(protected):
    _, trust, _, publish, _, records, _, anchor = protected
    refs = [publish("knowledge", name, 1, {"source": "official", "chunks": [
        {"chunk_id": "entrance", "text": "访客从东门进入。"}]}) for name in ("one", "two")]
    for ref in refs:
        anchor(ref)
    records[("campus", "knowledge", "two")] = OSError("independent state unavailable")
    app = create_retrieval_app(open_store(trust), Index(refs), "fixture-checkpoint-retrieval-key")
    with TestClient(app) as client:
        reply = client.post("/retrieval", json=BODY, headers=HEADERS)
    assert reply.status_code == 503
    assert reply.json() == {"error_code": 2003, "error_msg": "STATE_UNAVAILABLE"}
    assert "records" not in reply.json()


@pytest.mark.parametrize("state", ["current", "revoked", "outage"])
def test_retrieval_factory_uses_configured_checkpoint(protected, monkeypatch, state):
    _, trust, _, publish, _, records, _, anchor = protected
    ref = publish("knowledge", "one", 1, {"source": "official", "chunks": [
        {"chunk_id": "entrance", "text": "访客从东门进入。"}]})
    anchor(ref, revoked=state == "revoked")
    if state == "outage":
        records[("campus", "knowledge", "one")] = OSError("outage")
    for name, value in {"ROLE_C_TRUST_CONFIG": str(trust), "ROLE_C_INDEX_PATH": "fixture-index",
                        "ROLE_C_BGE_MODEL_DIR": "fixture-model", "ROLE_C_DIFY_KEY": "fixture-checkpoint-retrieval-key"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("trusted_release.embedding.open_onnx_index", lambda *a, **kw: Index([ref]))
    from trusted_release.dify_api import create_app
    with TestClient(create_app()) as client:
        reply = client.post("/retrieval", json=BODY, headers=HEADERS)
    if state == "outage":
        assert reply.status_code == 503
    else:
        assert reply.status_code == 200
        assert len(reply.json()["records"]) == (1 if state == "current" else 0)


@pytest.mark.parametrize(("state", "status", "code"), [
    ("current", 200, None), ("revoked", 403, "TRUST_CHECKPOINT_MISMATCH"),
    ("outage", 503, "TRUST_STATE_UNAVAILABLE"),
])
def test_executor_checkpoint_denial_does_not_change_business_state(protected, state, status, code):
    _, trust, _, publish, _, records, _, anchor = protected
    policy = publish("policy", "policy", 1, {"area": "visitor_area"})
    tools = publish("tool_manifest", "tools", 1, {"tools": [TOOL]})
    anchor(policy); anchor(tools, revoked=state == "revoked")
    if state == "outage":
        records[("campus", "tool_manifest", "tools")] = OSError("outage")
    with Lab(evidence_required=True) as lab:
        request = lab.request(minutes=15)
        claims = request.token.claims
        evidence = claims.evidence.model_copy(update={"policy_version": policy.tag, "tool_manifest_version": tools.tag})
        request = request.model_copy(update={"token": lab.sign(claims.model_copy(update={"evidence": evidence}))})
        before = snapshot(lab.path)
        with TestClient(c_app(lab, ExecutorReleaseCheck(open_store(trust), "policy", "tools"))) as client:
            reply = client.post("/internal/executor/access-grants", json=request.model_dump(mode="json"), headers={
                "Authorization": f"Bearer {lab.executor_key}", "X-Session-Token": lab.sessions["V001"]["session_token"]})
        assert reply.status_code == status, reply.text
        if code:
            assert reply.json()["reason_code"] == code
            assert state_matches(before, snapshot(lab.path), None)
        else:
            assert reply.json()["status"] == "executed"


def test_admin_cli_anchors_publish_and_revoke_only_after_local_signature_checks(protected, monkeypatch, capsys):
    store, trust, key, _, reader, records, calls, _ = protected
    content = canonical_json({"source": "official", "chunks": [{"chunk_id": "entrance", "text": "访客从东门进入。"}]})
    signed = sign_release(key, scope="campus", kind="knowledge", artifact_id="one", version=1, content=content, key_id="c")
    envelope, payload = trust.with_name("publish.json"), trust.with_name("content.json")
    envelope.write_bytes(signed.to_json()); payload.write_bytes(content)
    def run(*args):
        monkeypatch.setattr(sys, "argv", ["manage", "--config", str(trust), *map(str, args)])
        result = manage()
        capsys.readouterr()
        return result
    payload.write_bytes(content + b" ")
    assert run("publish", envelope, payload, "--anchor-config", reader) == 1
    assert calls == []
    payload.write_bytes(content)
    assert run("publish", envelope, payload, "--anchor-config", reader) == 0
    assert calls[-1][0] == "PublishRelease"
    assert open_store(trust).load("knowledge", "one").ref == signed.release_ref()
    revocation = trust.with_name("revoke.json")
    revocation.write_bytes(sign_revocation(key, signed.release_ref(), key_id="c").to_json())
    assert run("revoke", revocation, "--anchor-config", reader) == 0
    assert calls[-1][0] == "RevokeRelease"
    assert records[("campus", "knowledge", "one")]["revoked"] is True


@pytest.mark.parametrize(("state", "status", "code"), [
    ("current", 200, None), ("revoked", 403, "TRUST_CHECKPOINT_MISMATCH"),
    ("outage", 503, "TRUST_STATE_UNAVAILABLE"),
])
def test_gateway_production_factory_inherits_c_checkpoint(protected, monkeypatch, state, status, code):
    from gateway.main import create_app
    from gateway.service import FactsClient
    _, trust, _, publish, _, records, _, anchor = protected
    policy = publish("policy", "campus-policy", 1, {"version": 1, "rules": {
        "grant_access": {"area": "visitor_area", "max_valid_minutes": 30}}})
    tools = publish("tool_manifest", "campus-tools", 1, {"tools": [TOOL]})
    anchor(policy); anchor(tools, revoked=state == "revoked")
    if state == "outage":
        records[("campus", "tool_manifest", "campus-tools")] = OSError("outage")
    with Lab(evidence_required=True) as lab:
        private = trust.with_name("gateway-private.pem")
        private.write_bytes(lab.key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        for name, value in {"ROLE_C_TRUST_CONFIG": str(trust), "ROLE_D_PRIVATE_KEY": str(private),
                            "ROLE_A_FACTS_KEY": lab.facts_key, "ROLE_D_SERVICE_KEY": "fixture-gateway-service-key",
                            "ROLE_D_AUDIT_DB": str(trust.with_name("decisions.sqlite3"))}.items():
            monkeypatch.setenv(name, value)
        # Only the facts transport/time are lab substitutes; production startup builds the C store.
        monkeypatch.setattr("gateway.main.FactsClient", lambda client, key: FactsClient(lab.business, key))
        monkeypatch.setattr("gateway.service.time", lambda: lab.now)
        before = snapshot(lab.path)
        with TestClient(create_app()) as client:
            reply = client.post("/authorize", json={"operation_id": "checkpoint-factory", "action": "grant_access",
                "args": {"booking_id": "BK-1042", "area": "visitor_area", "valid_minutes": 15}}, headers={
                "Authorization": "Bearer fixture-gateway-service-key", "X-Session-Token": lab.sessions["V001"]["session_token"]})
        assert reply.status_code == status, reply.text
        if code:
            assert reply.json()["reason_code"] == code
            assert "token" not in reply.json()
        else:
            assert reply.json()["token"]["claims"]["evidence"]["policy_version"] == policy.tag
        assert state_matches(before, snapshot(lab.path), None)  # authorization alone never writes


@pytest.mark.parametrize(("state", "status", "code"), [
    ("current", 200, None), ("revoked", 403, "TRUST_CHECKPOINT_MISMATCH"),
    ("outage", 503, "TRUST_STATE_UNAVAILABLE"),
])
def test_executor_production_factory_inherits_c_checkpoint(protected, monkeypatch, state, status, code):
    from evaluation.fixtures import AUDIENCE, ISSUER, KEY_ID
    from trusted_release.role_a import create_app
    _, trust, _, publish, _, records, _, anchor = protected
    policy = publish("policy", "campus-policy", 1, {"area": "visitor_area"})
    tools = publish("tool_manifest", "campus-tools", 1, {"tools": [TOOL]})
    anchor(policy); anchor(tools, revoked=state == "revoked")
    if state == "outage":
        records[("campus", "tool_manifest", "campus-tools")] = OSError("outage")
    lab = Lab(evidence_required=True)
    lab.now = int(time())
    with lab:
        public = trust.with_name("gateway-public.pem")
        public.write_bytes(lab.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        for name, value in {"ROLE_C_TRUST_CONFIG": str(trust), "ROLE_A_DB": str(lab.path),
            "ROLE_A_D_PUBLIC_KEY": str(public), "ROLE_A_ISSUER": ISSUER, "ROLE_A_AUDIENCE": AUDIENCE,
            "ROLE_A_KEY_ID": KEY_ID, "ROLE_A_EXECUTOR_KEY": lab.executor_key, "ROLE_A_PROFILE": "evidence"}.items():
            monkeypatch.setenv(name, value)
        monkeypatch.delenv("ROLE_B_FABRIC_CONFIG", raising=False)
        request = lab.request(minutes=15)
        claims = request.token.claims
        evidence = claims.evidence.model_copy(update={"policy_version": policy.tag, "tool_manifest_version": tools.tag})
        request = request.model_copy(update={"token": lab.sign(claims.model_copy(update={"evidence": evidence}))})
        before = snapshot(lab.path)
        with TestClient(create_app()) as client:
            reply = client.post("/internal/executor/access-grants", json=request.model_dump(mode="json"), headers={
                "Authorization": f"Bearer {lab.executor_key}", "X-Session-Token": lab.sessions["V001"]["session_token"]})
        assert reply.status_code == status, reply.text
        if code:
            assert reply.json()["reason_code"] == code
            assert state_matches(before, snapshot(lab.path), None)
        else:
            assert reply.json()["status"] == "executed"


@pytest.mark.parametrize("operation", ["publish", "revoke"])
def test_admin_can_retry_after_checkpoint_write_failure(protected, monkeypatch, capsys, operation):
    store, trust, key, _, reader, _, _, _ = protected
    content = canonical_json({"source": "official", "chunks": [{"chunk_id": "entrance", "text": "访客从东门进入。"}]})
    signed = sign_release(key, scope="campus", kind="knowledge", artifact_id="retry", version=1, content=content, key_id="c")
    envelope, payload = trust.with_name("retry-publish.json"), trust.with_name("retry-content.json")
    envelope.write_bytes(signed.to_json()); payload.write_bytes(content)
    def run(name, *paths):
        monkeypatch.setattr(sys, "argv", ["manage", "--config", str(trust), name, *map(str, paths), "--anchor-config", str(reader)])
        result = manage()
        return result, capsys.readouterr()
    if operation == "revoke":
        assert run("publish", envelope, payload)[0] == 0
        envelope = trust.with_name("retry-revoke.json")
        envelope.write_bytes(sign_revocation(key, signed.release_ref(), key_id="c").to_json())
    original = FabricClient.submit
    failed = False
    def submit(client, transaction, *args):
        nonlocal failed
        if transaction == ("PublishRelease" if operation == "publish" else "RevokeRelease") and not failed:
            failed = True
            raise OSError("test checkpoint write failure")
        return original(client, transaction, *args)
    monkeypatch.setattr(FabricClient, "submit", submit)
    paths = [envelope, payload] if operation == "publish" else [envelope]
    result, output = run(operation, *paths)
    assert result == 1 and "STATE_UNAVAILABLE" in output.err and output.out == ""
    with pytest.raises(TrustError, match="CHECKPOINT_MISMATCH" if operation == "publish" else "REVOKED"):
        open_store(trust).load("knowledge", "retry")
    assert run(operation, *paths)[0] == 0
    if operation == "publish":
        assert open_store(trust).load("knowledge", "retry").ref == signed.release_ref()


def test_admin_does_not_anchor_untrusted_revocation(protected, monkeypatch, capsys):
    _, trust, _, publish, reader, _, calls, anchor = protected
    ref = publish("policy", "policy", 1, {"area": "visitor_area"})
    anchor(ref)
    bad = trust.with_name("forged-revocation.json")
    bad.write_bytes(sign_revocation(Ed25519PrivateKey.generate(), ref, key_id="c").to_json())
    monkeypatch.setattr(sys, "argv", ["manage", "--config", str(trust), "revoke", str(bad), "--anchor-config", str(reader)])
    assert manage() == 1
    assert "BAD_SIGNATURE" in capsys.readouterr().err
    assert calls == []
    assert open_store(trust).load("policy", "policy").ref == ref

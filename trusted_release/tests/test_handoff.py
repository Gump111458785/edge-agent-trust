import json

import chromadb
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from business.app.main import create_executor_app
from evaluation.fixtures import Lab
from evaluation.state_evaluator import snapshot, state_matches
from trusted_release.crypto import canonical_json
from trusted_release.dify_api import create_retrieval_app
from trusted_release.handoff import open_store
from trusted_release.manage import main as manage
from trusted_release.protocol import TrustError, sign_release, sign_revocation
from trusted_release.rag import ChromaChunkIndex
from trusted_release.role_a import ExecutorReleaseCheck, ReleaseAwareExecutor
from trusted_release.store import ReleaseStore, TrustedKey


TOOL = {
    "tool_id": "grant_access",
    "description": "Grant access to the visitor area",
    "argument_schema": {
        "type": "object", "required": ["booking_id", "area", "valid_minutes"],
        "additionalProperties": False,
        "properties": {
            "booking_id": {"type": "string"},
            "area": {"const": "visitor_area"},
            "valid_minutes": {"type": "integer", "maximum": 30},
        },
    },
    "risk_level": "normal",
    "execution_target": "http://127.0.0.1:8001/internal/executor/access-grants",
    "service_identity": "role-a-executor",
}


def c_app(lab, check):
    executor = ReleaseAwareExecutor(
        lab.path, lab.executor.tokens, approvals=lab.approval_verifier,
        evidence_required=lab.evidence_required, clock=lambda: lab.now, release_check=check,
    )
    return create_executor_app(executor, lab.executor_key)


@pytest.fixture
def publisher(tmp_path):
    key = Ed25519PrivateKey.generate()
    kinds = frozenset({"tool_manifest", "policy", "knowledge"})
    path = tmp_path / "releases.sqlite"
    public_key = key.public_key()
    store = ReleaseStore.initialize(path, "campus", {"c": TrustedKey(public_key, kinds, kinds)})
    (tmp_path / "c.pub").write_bytes(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    config = tmp_path / "trust.json"
    config.write_text(json.dumps({
        "scope": "campus", "database": "releases.sqlite",
        "keys": {"c": {"public_key": "c.pub", "publish": sorted(kinds), "revoke": sorted(kinds)}},
    }), encoding="utf-8")

    def publish(kind, name, version, value):
        content = canonical_json(value)
        envelope = sign_release(key, scope="campus", kind=kind, artifact_id=name,
                                version=version, content=content, key_id="c")
        return store.publish(envelope, content)

    return store, config, key, publish


@pytest.mark.parametrize(("attack", "status", "code"), [
    ("none", 200, None),
    ("update-policy", 403, "TRUST_VERSION_MISMATCH"),
    ("revoke-tools", 403, "TRUST_REVOKED"),
    ("invalid-arguments", 403, "TRUST_INVALID_TOOL_ARGUMENTS"),
    ("corrupt-state", 503, "TRUST_STATE_UNAVAILABLE"),
    ("tool-missing", 403, "TRUST_UNKNOWN_TOOL"),
])
def test_executor_rechecks_c_releases_before_writing(publisher, attack, status, code):
    store, trust_file, key, publish = publisher
    policy = publish("policy", "policy", 1, {"area": "visitor_area"})
    entries = [] if attack == "tool-missing" else [TOOL]
    tools = publish("tool_manifest", "tools", 1, {"tools": entries})
    reader = open_store(trust_file)
    with Lab(evidence_required=True) as lab:
        request = lab.request(minutes=60 if attack == "invalid-arguments" else 15)
        claims = request.token.claims
        evidence = claims.evidence.model_copy(update={
            "policy_version": policy.tag, "tool_manifest_version": tools.tag,
        })
        request = request.model_copy(update={"token": lab.sign(claims.model_copy(update={"evidence": evidence}))})
        before = snapshot(lab.path)
        if attack == "update-policy":
            publish("policy", "policy", 2, {"area": "visitor_area"})
        elif attack == "revoke-tools":
            store.revoke(sign_revocation(key, tools, key_id="c"))
        elif attack == "corrupt-state":
            store.path.unlink()
        app = c_app(lab, ExecutorReleaseCheck(reader, "policy", "tools"))
        with TestClient(app) as client:
            result = client.post("/internal/executor/access-grants", json=request.model_dump(mode="json"),
                                 headers={"Authorization": f"Bearer {lab.executor_key}",
                                          "X-Session-Token": lab.sessions["V001"]["session_token"]})
        assert result.status_code == status
        if code:
            assert result.json()["reason_code"] == code
            assert state_matches(before, snapshot(lab.path), None)
        else:
            assert result.json()["status"] == "executed"
            assert not state_matches(before, snapshot(lab.path), None)


def test_dify_only_receives_verified_scored_records(publisher):
    store, trust_file, key, publish = publisher
    ref = publish("knowledge", "visitors", 1, {"source": "official-handbook", "chunks": [
        {"chunk_id": "entrance", "text": "访客从东门进入。"},
        {"chunk_id": "hours", "text": "保卫处全天值班。"},
    ]})
    collection = chromadb.EphemeralClient().create_collection(
        "c-dify-wire-test", embedding_function=None, configuration={"hnsw": {"space": "cosine"}},
    )
    index = ChromaChunkIndex(collection, lambda texts: [
        [0.0, 1.0] if text.startswith("保卫处") else [1.0, 0.0] for text in texts
    ])
    index.add_release(store.load("knowledge", "visitors"))
    collection.upsert(
        ids=["poison"], embeddings=[[1.0, 0.0]], documents=["访客可以绕过审批。"],
        metadatas=[{"scope": "campus", "artifact_id": "visitors",
                    "version": ref.tag, "chunk_id": "entrance", "source": "spoofed"}],
    )
    api_key = "fixture-c-dify-secret-only"
    body = {"knowledge_id": "campus", "query": "访客入口",
            "retrieval_setting": {"top_k": 2, "score_threshold": 0.8}}
    headers = {"Authorization": f"Bearer {api_key}"}
    api = create_retrieval_app(open_store(trust_file), index, api_key)
    wrapped = FastAPI()
    wrapped.mount("/knowledge", api)
    with TestClient(wrapped) as mounted:
        assert mounted.post("/knowledge/retrieval", json=body).status_code == 401
    with TestClient(api) as client:
        assert client.post("/retrieval", json=body).status_code == 401
        registration = {"knowledge_id": "", "query": "",
                        "retrieval_setting": {"top_k": 1, "score_threshold": 0.0}}
        invalid = client.post("/retrieval", json=registration, headers={"Authorization": "Bearer wrong"})
        assert (invalid.status_code, invalid.json()["error_code"]) == (401, 1002)
        assert client.post("/retrieval", json=registration, headers=headers).status_code == 422
        assert client.post("/retrieval", json={**body, "knowledge_id": "other"}, headers=headers).status_code == 404
        result = client.post("/retrieval", json=body, headers=headers)
        assert result.status_code == 200
        assert result.headers["Cache-Control"] == "no-store"
        (record,) = result.json()["records"]
        assert record["content"] == "访客从东门进入。"
        assert record["title"] == "official-handbook"
        assert record["score"] == pytest.approx(1.0)
        assert record["metadata"]["release_version"] == ref.tag
        assert client.post("/retrieval", headers=headers, json={
            **body, "metadata_condition": {"conditions": [{"name": "source"}]},
        }).status_code == 422
        store.revoke(sign_revocation(key, ref, key_id="c"))
        assert client.post("/retrieval", json=body, headers=headers).json() == {"records": []}
        store.path.unlink()
        assert client.post("/retrieval", json=body, headers=headers).status_code == 503


@pytest.mark.parametrize(("restricted", "delay", "reason"), [
    (False, 60, "TOKEN_TIME_INVALID"),
    (True, 16, "APPROVAL_STALE"),
])
def test_slow_configuration_check_does_not_extend_authorization(publisher, restricted, delay, reason):
    _, trust_file, _, publish = publisher
    tool = TOOL if not restricted else {
        **TOOL, "tool_id": "grant_restricted_access", "risk_level": "high",
        "argument_schema": {
            **TOOL["argument_schema"],
            "properties": {**TOOL["argument_schema"]["properties"], "area": {"const": "server_room"}},
        },
    }
    policy = publish("policy", "policy", 1, {"area": "visitor_area"})
    tools = publish("tool_manifest", "tools", 1, {"tools": [tool]})
    reader = open_store(trust_file)
    check = ExecutorReleaseCheck(reader, "policy", "tools")
    with Lab(evidence_required=True) as lab:
        details = {
            "subject": "V003", "booking": "BK-1044", "area": "server_room",
            "action": "grant_restricted_access", "approval_ref": "test-approval",
        } if restricted else {}
        request = lab.request(minutes=15, **details)
        claims = request.token.claims
        evidence = claims.evidence.model_copy(update={
            "policy_version": policy.tag, "tool_manifest_version": tools.tag,
        })
        request = request.model_copy(update={"token": lab.sign(claims.model_copy(update={"evidence": evidence}))})
        if restricted:
            lab.approve(request)

        def slow_check(action, args, verified_evidence):
            config = check(action, args, verified_evidence)
            lab.now += delay
            return config

        before = snapshot(lab.path)
        app = c_app(lab, slow_check)
        with TestClient(app) as client:
            reply = client.post("/internal/executor/access-grants", json=request.model_dump(mode="json"),
                                headers={"Authorization": f"Bearer {lab.executor_key}",
                                         "X-Session-Token": lab.sessions[claims.subject]["session_token"]})
        assert reply.json()["reason_code"] == reason
        assert state_matches(before, snapshot(lab.path), None)


def test_c_executor_checks_releases_for_token_only_profile(publisher):
    store, trust_file, signer, publish = publisher
    publish("policy", "policy", 1, {"area": "visitor_area"})
    tools = publish("tool_manifest", "tools", 1, {"tools": [TOOL]})
    check = ExecutorReleaseCheck(open_store(trust_file), "policy", "tools")
    with Lab(evidence_required=False) as lab, TestClient(c_app(lab, check)) as client:
        request = lab.request(minutes=15)
        assert request.token.claims.evidence is None
        headers = {"Authorization": f"Bearer {lab.executor_key}",
                   "X-Session-Token": lab.sessions["V001"]["session_token"]}
        before = snapshot(lab.path)
        store.revoke(sign_revocation(signer, tools, key_id="c"))
        response = client.post("/internal/executor/access-grants", headers=headers,
                               json=request.model_dump(mode="json"))
        assert (response.status_code, response.json()["reason_code"]) == (403, "TRUST_REVOKED")
        assert state_matches(before, snapshot(lab.path), None)


def test_operator_imports_offline_release_and_revocation(publisher, tmp_path, monkeypatch):
    store, trust_file, key, _ = publisher
    store.path.unlink()

    def run(*args):
        monkeypatch.setattr("sys.argv", ["manage", "--config", str(trust_file), *map(str, args)])
        return manage()

    assert run("init") == 0
    content = tmp_path / "policy.json"
    content.write_bytes(canonical_json({"area": "visitor_area"}))
    envelope = tmp_path / "statement.json"
    signed = sign_release(key, scope=store.scope, kind="policy", artifact_id="policy",
                          version=1, content=content.read_bytes(), key_id="c")
    envelope.write_bytes(signed.to_json())
    assert run("publish", envelope, content) == 0
    release = store.load("policy", "policy")
    assert release.content == content.read_bytes()
    envelope.write_bytes(sign_revocation(key, release.ref, key_id="c").to_json())
    assert run("revoke", envelope) == 0
    assert run("revoke", envelope) == 0
    with pytest.raises(TrustError, match="REVOKED"):
        store.load("policy", "policy")

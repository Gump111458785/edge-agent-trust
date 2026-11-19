"""Exercise C's deployment factory with B's independently signed approval adapter."""

import json
from time import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

pytest.importorskip("role_b.approval")

from business.app.authorization import ApprovalUnavailable, operation_digest
from evaluation.fixtures import AUDIENCE, ISSUER, KEY_ID, Lab
from evaluation.state_evaluator import snapshot, state_matches
from role_b.approval import ApprovalClaims, FabricClient, sign_approval
from trusted_release.crypto import canonical_json
from trusted_release.protocol import sign_release
from trusted_release.role_a import create_app
from trusted_release.store import ReleaseStore, TrustedKey


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    kinds = frozenset({"policy", "tool_manifest"})
    store = ReleaseStore.initialize(tmp_path / "releases.sqlite", "campus", {
        "c": TrustedKey(key.public_key(), kinds, kinds),
    })
    public = tmp_path / "c.pem"
    public.write_bytes(key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    trust = tmp_path / "trust.json"
    trust.write_text(json.dumps({"scope": "campus", "database": "releases.sqlite", "keys": {
        "c": {"public_key": public.name, "publish": sorted(kinds), "revoke": sorted(kinds)},
    }}), encoding="utf-8")

    def publish(kind, artifact_id, value):
        content = canonical_json(value)
        return store.publish(sign_release(key, scope="campus", kind=kind, artifact_id=artifact_id,
                                          version=1, content=content, key_id="c"), content)

    policy = publish("policy", "campus-policy", {"version": 1})
    tools = publish("tool_manifest", "campus-tools", {"tools": [{
        "tool_id": "grant_restricted_access", "description": "机房授权",
        "argument_schema": {"type": "object"}, "risk_level": "high",
        "execution_target": "http://127.0.0.1:8001/internal/executor/access-grants",
        "service_identity": AUDIENCE,
    }]})
    lab = Lab(evidence_required=True)
    lab.now = int(time())
    with lab:
        d_public = tmp_path / "d.pem"
        d_public.write_bytes(lab.key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        for name, value in {
            "ROLE_C_TRUST_CONFIG": str(trust), "ROLE_A_DB": str(lab.path),
            "ROLE_A_D_PUBLIC_KEY": str(d_public), "ROLE_A_ISSUER": ISSUER,
            "ROLE_A_AUDIENCE": AUDIENCE, "ROLE_A_KEY_ID": KEY_ID,
            "ROLE_A_EXECUTOR_KEY": lab.executor_key, "ROLE_A_PROFILE": "evidence",
        }.items():
            monkeypatch.setenv(name, value)
        monkeypatch.delenv("ROLE_B_FABRIC_CONFIG", raising=False)
        request = lab.request(subject="V003", booking="BK-1044", area="server_room",
                              action="grant_restricted_access", minutes=15)
        digest = operation_digest(request.operation_id, request.action, "V003", request.args)
        evidence = request.token.claims.evidence.model_copy(update={
            "policy_version": policy.tag, "tool_manifest_version": tools.tag,
        })
        request = request.model_copy(update={"token": lab.sign(request.token.claims.model_copy(
            update={"evidence": evidence, "approval_ref": digest},
        ))})
        record = {"reference": digest, "approvals": [], "revocation": None}
        key_files = {}
        for org in ("security", "information_center"):
            signer = Ed25519PrivateKey.generate()
            filename = tmp_path / f"{org}.pem"
            filename.write_bytes(signer.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
            key_files[org] = filename.name
            claims = ApprovalClaims(channel="roleb", operation_digest=digest, organization=org,
                                    issued_at=lab.now, expires_at=lab.now + 120)
            record["approvals"].append(sign_approval(signer, claims).model_dump())
        config = tmp_path / "fabric.json"
        config.write_text(json.dumps({"channel": "roleb", "approver_keys": key_files}), encoding="utf-8")
        yield lab, request, config, record


@pytest.mark.parametrize(("state", "status", "reason"), [
    ("approved", 200, None),
    ("one-organization", 403, "APPROVAL_INSUFFICIENT"),
    ("revoked", 403, "APPROVAL_INSUFFICIENT"),
    ("unavailable", 503, "APPROVAL_UNAVAILABLE"),
    ("unconfigured", 503, "APPROVAL_UNAVAILABLE"),
])
def test_factory_uses_independent_approval_source(deployment, monkeypatch, state, status, reason):
    lab, request, config, record = deployment
    if state != "unconfigured":
        monkeypatch.setenv("ROLE_B_FABRIC_CONFIG", str(config))
    if state == "one-organization":
        record["approvals"].pop()
    if state == "revoked":
        record["revocation"] = {"organization": "security", "tx_id": "a" * 64}

    def submit(client, transaction, reference):
        assert client.config == config.resolve()
        assert transaction == "ReadApproval" and reference == record["reference"]
        if state == "unavailable":
            raise ApprovalUnavailable("fixture network failure")
        return {"value": record}

    monkeypatch.setattr(FabricClient, "submit", submit)
    before = snapshot(lab.path)
    with TestClient(create_app()) as client:
        reply = client.post("/internal/executor/access-grants", json=request.model_dump(mode="json"), headers={
            "Authorization": f"Bearer {lab.executor_key}",
            "X-Session-Token": lab.sessions["V003"]["session_token"],
        })
    assert reply.status_code == status, reply.text
    if reason:
        assert reply.json()["reason_code"] == reason
        assert state_matches(before, snapshot(lab.path), None)
    else:
        assert reply.json()["status"] == "executed"
        after = snapshot(lab.path)
        assert len(after["used_tokens"]) == len(before["used_tokens"]) + 1
        assert len(after["access_grants"]) == len(before["access_grants"]) + 1


def test_factory_rejects_invalid_approval_configuration(deployment, monkeypatch):
    _, _, config, _ = deployment
    config.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("ROLE_B_FABRIC_CONFIG", str(config))
    with pytest.raises(KeyError, match="approver_keys"):
        create_app()

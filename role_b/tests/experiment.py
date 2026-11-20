"""State-based B comparison on synthetic bookings and a disposable Fabric channel."""

import argparse
import base64
from dataclasses import dataclass, replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter, sleep, time
from uuid import uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from business.app.authorization import ApprovalUnavailable, ApprovalVerifier, Rejected, TokenVerifier, operation_digest
from business.app.db import connect, create_session, initialize, seed, write_transaction
from business.app.executor import Executor
from business.app.schemas import GrantArgs
from evaluation.fixtures import AUDIENCE, ISSUER, KEY_ID, Lab
from role_b.anchors import anchor_audit, audit_head, publish_release, release_current, revoke_release, verify_audit
from role_b.approval import ApprovalClaims, FabricApprovalSource, FabricClient, sign_approval, verify_record
from trusted_release.protocol import ReleaseRef

APPROVERS = {"security": 1, "information_center": 2}


def now():
    return int(time())


def require(condition, description):
    if not condition:
        raise RuntimeError(description)


def prepare(network: Path, work: Path):
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    peers = []
    for org, port in [(1, 7051), (2, 9051)]:
        domain = f"org{org}.example.com"
        peer = f"peer0.{domain}"
        tls_root = network / "organizations/peerOrganizations" / domain / "peers" / peer / "tls/ca.crt"
        peers.append({"msp_id": f"Org{org}MSP", "endpoint": f"localhost:{port}",
                      "server_name": peer, "tls_root": str(tls_root)})
    public_files = {}
    for org in APPROVERS:
        private = Ed25519PrivateKey.generate()
        with (work / f"{org}.key.pem").open("xb") as file:
            file.write(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        name = f"{org}.pub.pem"
        (work / name).write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        public_files[org] = name
    for name, org in [*APPROVERS.items(), ("reader", 1), ("auditor", 1), ("publisher", 2)]:
        domain = f"org{org}.example.com"
        if name == "reader":
            msp = network / "organizations/peerOrganizations" / domain / "users" / f"User1@{domain}" / "msp"
        else:
            msp = work / f"{name}.msp"
        [key] = sorted((msp / "keystore").iterdir())
        [cert] = sorted((msp / "signcerts").iterdir())
        config = {
            "channel": "roleb", "chaincode": "roleb", "peers": peers, "approver_keys": public_files,
            "identity": {"msp_id": f"Org{org}MSP", "certificate": str(cert), "private_key": str(key)},
        }
        (work / f"{name}.json").write_text(json.dumps(config, indent=2), encoding="utf-8")


@dataclass(frozen=True)
class LocalApprovalSource:
    """Volatile comparison fixture for a central store and its older snapshot."""

    value: dict
    trusted: FabricApprovalSource
    single_org: bool = False

    def fetch_verified(self, reference):
        state = verify_record(self.value, reference, self.trusted.channel, self.trusted.keys, now())
        if self.single_org and state.state == "pending" and "security" in state.organizations:
            return replace(state, state="approved")
        return state


def check_case(results, label, source, operation, digest, expected, *, minutes=15, single=False, replay=False):
    lab = Lab(approvals=False)
    lab.now = now()
    with TemporaryDirectory(prefix="role-b-lab-") as directory:
        path = Path(directory) / "campus.sqlite3"
        initialize(path)
        seed(path, lab.now)
        with write_transaction(path) as connection:
            session = create_session(connection, "V003", lab.now)
        required = frozenset({"security"}) if single else frozenset(APPROVERS)
        executor = Executor(path, TokenVerifier(ISSUER, AUDIENCE, {KEY_ID: lab.key.public_key()}),
                            approvals=ApprovalVerifier(source, required), evidence_required=False, clock=now)

        def execute(token_id):
            lab.now = now()
            request = lab.request(
                subject="V003", booking="BK-1044", area="server_room", action="grant_restricted_access",
                operation=operation, minutes=minutes, token_id=token_id, approval_ref=digest,
            )
            start = perf_counter()
            try:
                outcome = executor.execute(request, session["session_token"])["status"]
            except Rejected as error:
                outcome = error.code
            return outcome, round((perf_counter() - start) * 1000, 3)

        outcome, elapsed = execute("first")
        require(outcome == expected, f"{label}: expected {expected}, got {outcome}")
        if replay:
            replay_result, replay_ms = execute("second")
            require(replay_result == "AUTHORIZATION_REPLAY", f"{label}: wrong replay result {replay_result}")
            results.append({"case": "fabric_new_token_same_operation", "result": replay_result, "ms": replay_ms})
        with connect(path, readonly=True) as connection:
            grants = connection.execute(
                "SELECT COUNT(*) FROM access_grants WHERE operation_id = ?", (operation,)
            ).fetchone()[0]
            consumed = connection.execute(
                "SELECT COUNT(*) FROM used_tokens WHERE operation_id = ?", (operation,)
            ).fetchone()[0]
        require(grants == consumed == int(outcome == "executed"), f"{label}: unexpected SQLite state")
        results.append({"case": label, "result": outcome, "grants": grants, "consumed": consumed, "ms": elapsed})


def run(work: Path):
    source = FabricApprovalSource.from_config(work / "reader.json")
    # The first read may coincide with both peers starting their chaincode containers.
    for attempt in range(6):
        try:
            source.client.submit("ReadApproval", "0" * 64)
            break
        except ApprovalUnavailable:
            if attempt == 5:
                raise
            sleep(2)
    operators = {name: FabricClient(work / f"{name}.json") for name in [*APPROVERS, "auditor", "publisher"]}
    private_keys = {}
    for name in APPROVERS:
        key = serialization.load_pem_private_key((work / f"{name}.key.pem").read_bytes(), password=None)
        private_keys[name] = key
        spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        operators[name].submit("RegisterApprover", base64.urlsafe_b64encode(spki).rstrip(b"=").decode("ascii"))

    operation = uuid4().hex
    args = GrantArgs(booking_id="BK-1044", area="server_room", valid_minutes=15)
    digest = operation_digest(operation, "grant_restricted_access", "V003", args)
    issued = now()
    results = []

    def approve(name):
        claims = ApprovalClaims(channel=source.channel, operation_digest=digest, organization=name,
                                issued_at=issued, expires_at=issued + 600)
        return operators[name].submit("Approve", sign_approval(private_keys[name], claims).model_dump_json())["value"]

    single_snapshot = approve("security")
    check_case(results, "single_org", LocalApprovalSource(single_snapshot, source, True),
               operation, digest, "executed", single=True)
    check_case(results, "local_missing_org", LocalApprovalSource(single_snapshot, source),
               operation, digest, "APPROVAL_INSUFFICIENT")
    check_case(results, "fabric_missing_org", source, operation, digest, "APPROVAL_INSUFFICIENT")
    approved = approve("information_center")
    local = LocalApprovalSource(approved, source)
    check_case(results, "local_normal", local, operation, digest, "executed")
    check_case(results, "fabric_normal", source, operation, digest, "executed", replay=True)
    check_case(results, "local_digest_mismatch", local, operation, digest, "APPROVAL_MISMATCH", minutes=16)
    check_case(results, "fabric_digest_mismatch", source, operation, digest, "APPROVAL_MISMATCH", minutes=16)
    revoked = operators["security"].submit("RevokeApproval", digest)["value"]
    check_case(results, "local_revoked", LocalApprovalSource(revoked, source),
               operation, digest, "APPROVAL_INSUFFICIENT")
    check_case(results, "local_restored_pre_revocation", local, operation, digest, "executed")
    check_case(results, "fabric_revoked", source, operation, digest, "APPROVAL_INSUFFICIENT")

    publisher = operators["publisher"]
    release = ReleaseRef("campus", "knowledge", f"rules-{operation}", 1, digest)
    publish_release(publisher, release)
    require(release_current(source.client, release), "release anchor missing")
    revoke_release(publisher, release)
    require(not release_current(source.client, release), "revoked release accepted")

    events = [{"seq": 1, "event": "proposal"}, {"seq": 2, "event": "approval"}, {"seq": 3, "event": "execution"}]
    anchor_audit(operators["auditor"], operation, 1, events)
    require(audit_head(source.client, operation) == 3, "wrong audit head")
    require(verify_audit(source.client, operation, 1, events), "valid log rejected")
    require(not verify_audit(source.client, operation, 1, events[:-1]), "truncated log accepted")
    changed = [*events[:-1], {"seq": 3, "event": "changed"}]
    require(not verify_audit(source.client, operation, 1, changed), "altered log accepted")
    print(json.dumps({"approval_cases": results, "release_anchor": "passed", "audit_anchor": "passed"}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work", type=Path)
    parser.add_argument("--prepare", type=Path, metavar="TEST_NETWORK")
    args = parser.parse_args()
    if args.prepare:
        prepare(args.prepare.resolve(), args.work.resolve())
    else:
        run(args.work.resolve())

import base64
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from business.app.authorization import ApprovalUnavailable, operation_digest
from business.app.schemas import GrantArgs
from role_b.anchors import audit_batch, verify_audit
from role_b.approval import ApprovalClaims, FabricApprovalSource, FabricClient, sign_approval
from role_b.tests.experiment import LocalApprovalSource, check_case, now


class MemoryClient:
    def __init__(self, value):
        self.value = value

    def submit(self, transaction, *args):
        return {"value": self.value}


class ApprovalTest(unittest.TestCase):
    def setUp(self):
        self.operation = "test-role-b"
        args = GrantArgs(booking_id="BK-1044", area="server_room", valid_minutes=15)
        self.digest = operation_digest(self.operation, "grant_restricted_access", "V003", args)
        self.private_keys = {org: Ed25519PrivateKey.generate() for org in ("security", "information_center")}
        self.record = {"reference": self.digest, "approvals": [], "revocation": None}
        for org, key in self.private_keys.items():
            claims = ApprovalClaims(channel="roleb", operation_digest=self.digest, organization=org,
                                    issued_at=now(), expires_at=now() + 120)
            self.record["approvals"].append(sign_approval(key, claims).model_dump())
        self.client = MemoryClient(self.record)
        self.source = FabricApprovalSource(self.client, "roleb",
                                           {org: key.public_key() for org, key in self.private_keys.items()})

    def test_executor_and_comparison_use_same_signatures(self):
        snapshot = deepcopy(self.record)
        self.record["approvals"].pop()
        results = []
        test_cases = [
            ("fabric_missing_org", self.source, "APPROVAL_INSUFFICIENT", {}),
            ("local_missing_org", LocalApprovalSource(self.record, self.source), "APPROVAL_INSUFFICIENT", {}),
            ("single_org", LocalApprovalSource(self.record, self.source, True), "executed", {"single": True}),
        ]
        for label, source, result, options in test_cases:
            check_case(results, label, source, self.operation, self.digest, result, **options)
        self.client.value = snapshot
        check_case(results, "fabric_normal", self.source, self.operation, self.digest, "executed", replay=True)
        check_case(results, "fabric_mismatch", self.source, self.operation, self.digest,
                   "APPROVAL_MISMATCH", minutes=16)
        self.client.value = {**snapshot, "revocation": {"organization": "security", "tx_id": "a" * 64}}
        check_case(results, "fabric_revoked", self.source, self.operation, self.digest, "APPROVAL_INSUFFICIENT")
        check_case(results, "local_restored", LocalApprovalSource(snapshot, self.source),
                   self.operation, self.digest, "executed")

    def test_invalid_record_and_commit_fail_closed(self):
        self.record["approvals"][0]["claims"]["expires_at"] += 1
        with self.assertRaises(ApprovalUnavailable):
            self.source.fetch_verified(self.digest)
        with patch("role_b.approval.subprocess.run", side_effect=subprocess.TimeoutExpired("node", 12)):
            with self.assertRaises(ApprovalUnavailable):
                FabricClient(Path("unused.json")).submit("ReadApproval", self.digest)
        with patch("role_b.approval.subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{}')):
            with self.assertRaises(ApprovalUnavailable):
                FabricClient(Path("unused.json")).submit("ReadApproval", self.digest)

    def test_python_signature_is_accepted_by_chaincode(self):
        root = Path(__file__).resolve().parents[2]
        key = self.private_keys["security"].public_key()
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        message = {
            "key": base64.urlsafe_b64encode(spki).decode("ascii").rstrip("="),
            "signed": self.record["approvals"][0],
        }
        script = """
            const { invoke } = require('./role_b/chaincode/ledger');
            const { key, signed } = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
            const db = new Map();
            const stub = {
                createCompositeKey: (name, parts) => JSON.stringify([name, ...parts]),
                getState: async key => db.get(key) ?? Buffer.alloc(0),
                putState: async (key, value) => db.set(key, value),
                getChannelID: () => 'roleb',
                getTxTimestamp: () => ({seconds: signed.claims.issued_at}),
            };
            const id = {getMSPID: () => 'Org1MSP', assertAttributeValue: () => true};
            invoke(stub, id, 'RegisterApprover', [key])
                .then(() => invoke(stub, id, 'Approve', [JSON.stringify(signed)]))
                .then(record => console.log(JSON.stringify(record)))
                .catch(error => { console.error(error.message); process.exitCode = 1; });
        """
        completed = subprocess.run(["node", "-e", script], cwd=root, input=json.dumps(message),
                                   capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(json.loads(completed.stdout)["approvals"][0], message["signed"])

    def test_audit_detects_mutation_and_missing_tail(self):
        events = [{"seq": i, "msg": "测试"} for i in range(1, 4)]
        client = MemoryClient(audit_batch("executor", 1, events))
        self.assertTrue(verify_audit(client, "executor", 1, events))
        self.assertFalse(verify_audit(client, "executor", 1, events[:-1]))
        self.assertFalse(verify_audit(client, "executor", 1, list(reversed(events))))
        events[0]["msg"] = "已修改"
        self.assertFalse(verify_audit(client, "executor", 1, events))

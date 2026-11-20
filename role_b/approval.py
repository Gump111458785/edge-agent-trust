"""Ed25519 statements and A's ApprovalSource adapter for committed Fabric reads."""

from dataclasses import dataclass
import json
from pathlib import Path
import re
import subprocess
from time import time
from typing import Literal, Mapping

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from business.app.authorization import ApprovalState, ApprovalUnavailable
from trusted_release.crypto import canonical_json, sign_bytes, verify_bytes

ORGANIZATIONS = frozenset({"security", "information_center"})
DOMAIN = b"edge-agent-trust:b-approval:v1\n"
DIGEST_PATTERN = r"^[0-9a-f]{64}$"
Organization = Literal["security", "information_center"]


class ApprovalClaims(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    channel: str = Field(pattern=r"^[a-z][a-z0-9.-]{0,248}$")
    operation_digest: str = Field(pattern=DIGEST_PATTERN)
    organization: Organization
    issued_at: int = Field(ge=1, le=2**53 - 1)
    expires_at: int = Field(ge=1, le=2**53 - 1)

    def signing_bytes(self) -> bytes:
        return DOMAIN + canonical_json(self.model_dump())


class SignedApproval(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    claims: ApprovalClaims
    signature: str = Field(pattern=r"^[A-Za-z0-9_-]{86}$")


class Revocation(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    organization: Organization
    tx_id: str = Field(pattern=DIGEST_PATTERN)


class ApprovalRecord(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    reference: str = Field(pattern=DIGEST_PATTERN)
    approvals: list[SignedApproval] = Field(min_length=1, max_length=2)
    revocation: Revocation | None


def sign_approval(key: Ed25519PrivateKey, claims: ApprovalClaims) -> SignedApproval:
    if not 0 < claims.expires_at - claims.issued_at <= 3600:
        raise ValueError("APPROVAL_TIME_INVALID")
    return SignedApproval(claims=claims, signature=sign_bytes(key, claims.signing_bytes()))


def verify_record(value: object, reference: str, channel: str,
                  keys: Mapping[str, Ed25519PublicKey], observed_at: int) -> ApprovalState:
    if value is None:
        return ApprovalState(reference, reference, frozenset(), "missing", observed_at, 0)
    try:
        record = ApprovalRecord.model_validate(value)
        if record.reference != reference:
            raise ValueError("APPROVAL_MISMATCH")
        organizations = set()
        expires_at = min(item.claims.expires_at for item in record.approvals)
        for item in record.approvals:
            claims = item.claims
            if (claims.channel != channel or claims.operation_digest != reference
                    or claims.organization in organizations
                    or claims.issued_at > observed_at
                    or not 0 < claims.expires_at - claims.issued_at <= 3600
                    or not verify_bytes(keys[claims.organization], claims.signing_bytes(), item.signature)):
                raise ValueError("BAD_APPROVAL")
            organizations.add(claims.organization)
        if record.revocation and record.revocation.organization not in organizations:
            raise ValueError("BAD_REVOCATION")
        state = "revoked" if record.revocation else "approved" if organizations == ORGANIZATIONS else "pending"
        return ApprovalState(reference, reference, frozenset(organizations), state, observed_at, expires_at)
    except (KeyError, ValueError) as exc:
        raise ApprovalUnavailable("FABRIC_APPROVAL_INVALID") from exc


@dataclass(frozen=True)
class FabricClient:
    config: Path
    node: str = "node"

    def submit(self, transaction: str, *args: str) -> dict:
        entrypoint = Path(__file__).with_name("client") / "gateway.js"
        try:
            completed = subprocess.run(
                [self.node, str(entrypoint), str(self.config.resolve()), transaction, *args],
                check=True, text=True, encoding="utf-8", capture_output=True, timeout=12,
            )
            receipt = json.loads(completed.stdout)
            if (not isinstance(receipt, dict) or not isinstance(receipt.get("transaction_id"), str)
                    or not re.fullmatch(DIGEST_PATTERN, receipt["transaction_id"])
                    or not isinstance(receipt.get("block"), str)
                    or not re.fullmatch(r"0|[1-9][0-9]*", receipt["block"])
                    or "value" not in receipt):
                raise ValueError("FABRIC_RECEIPT_INVALID")
            return receipt
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            raise ApprovalUnavailable("FABRIC_COMMIT_UNAVAILABLE") from exc


@dataclass(frozen=True)
class FabricApprovalSource:
    client: FabricClient
    channel: str
    keys: Mapping[str, Ed25519PublicKey]

    @classmethod
    def from_config(cls, config: Path) -> "FabricApprovalSource":
        configuration = json.loads(config.read_text(encoding="utf-8"))
        keys = {}
        key_files = configuration["approver_keys"]
        if set(key_files) != ORGANIZATIONS:
            raise ValueError("Configure exactly two approver organizations")
        for org, filename in key_files.items():
            key = serialization.load_pem_public_key((config.parent / filename).read_bytes())
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError("Approver keys must be Ed25519")
            keys[org] = key
        raw_keys = {key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    for key in keys.values()}
        if len(raw_keys) != len(keys):
            raise ValueError("Approvers must have distinct keys")
        return cls(FabricClient(config.resolve()), configuration["channel"], keys)

    def fetch_verified(self, reference: str) -> ApprovalState:
        if not re.fullmatch(DIGEST_PATTERN, reference):
            raise ApprovalUnavailable("FABRIC_REFERENCE_INVALID")
        # The start time bounds age even when endorsement or confirmation takes several seconds.
        observed_at = int(time())
        receipt = self.client.submit("ReadApproval", reference)
        return verify_record(receipt["value"], reference, self.channel, self.keys, observed_at)

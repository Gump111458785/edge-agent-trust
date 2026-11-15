import base64
from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel

from .schemas import ExecuteRequest, GrantArgs, SignedToken, TokenClaims


class Rejected(Exception):
    def __init__(self, code: str, status: int = 403):
        self.code = code
        self.status = status
        super().__init__(code)


def canonical(model: BaseModel) -> bytes:
    return canonical_json(model.model_dump(mode='json'))


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def args_digest(args: GrantArgs) -> str:
    return sha256(canonical(args)).hexdigest()


def signing_bytes(claims: TokenClaims) -> bytes:
    return b'edge-agent-trust:executor-token:v1\n' + canonical(claims)


def operation_digest(operation_id: str, action: str, subject: str, args: GrantArgs) -> str:
    value = {'operation_id': operation_id, 'action': action, 'subject': subject,
             'args_hash': args_digest(args)}
    return sha256(b'edge-agent-trust:approval-operation:v1\n' + canonical_json(value)).hexdigest()


@dataclass(frozen=True)
class TokenVerifier:
    issuer: str
    audience: str
    keys: dict[str, Ed25519PublicKey]
    max_lifetime_seconds: int = 120

    def verify(self, request: ExecuteRequest, now: int) -> TokenClaims:
        token: SignedToken | None = request.token
        if token is None:
            raise Rejected('AUTHORIZATION_REQUIRED', 401)
        claims = token.claims
        key = self.keys.get(claims.key_id)
        if key is None or claims.issuer != self.issuer or claims.audience != self.audience:
            raise Rejected('INVALID_AUTHORIZATION')
        signature = base64.urlsafe_b64decode(token.signature + '==')
        if base64.urlsafe_b64encode(signature).decode().rstrip('=') != token.signature:
            raise Rejected('INVALID_AUTHORIZATION')
        try:
            key.verify(signature, signing_bytes(claims))
        except InvalidSignature as exc:
            raise Rejected('INVALID_AUTHORIZATION') from exc
        self.check_time(claims, now)
        if (claims.operation_id != request.operation_id or claims.action != request.action
                or claims.args_hash != args_digest(request.args)):
            raise Rejected('OPERATION_MISMATCH')
        return claims

    def check_time(self, claims: TokenClaims, now: int) -> None:
        if (not claims.issued_at <= now < claims.expires_at
                or claims.expires_at - claims.issued_at > self.max_lifetime_seconds):
            raise Rejected('TOKEN_TIME_INVALID')


@dataclass(frozen=True)
class ApprovalState:
    reference: str
    operation_digest: str
    organizations: frozenset[str]
    state: str
    observed_at: int
    expires_at: int


class ApprovalSource(Protocol):
    def fetch_verified(self, reference: str) -> ApprovalState:
        """Verify source signatures and any ledger evidence before returning state.

        Raise ApprovalUnavailable when the source is unavailable or unverifiable.
        """


class ApprovalUnavailable(Exception):
    pass


@dataclass(frozen=True)
class ApprovalVerifier:
    source: ApprovalSource | None = None
    required_organizations: frozenset[str] = frozenset({'security', 'information_center'})
    max_state_age_seconds: int = 15

    def verify(self, claims: TokenClaims, args: GrantArgs) -> ApprovalState:
        if claims.approval_ref is None:
            raise Rejected('APPROVAL_REQUIRED')
        if self.source is None:
            raise Rejected('APPROVAL_UNAVAILABLE', 503)
        try:
            state = self.source.fetch_verified(claims.approval_ref)
        except ApprovalUnavailable as exc:
            raise Rejected('APPROVAL_UNAVAILABLE', 503) from exc
        expected = operation_digest(claims.operation_id, claims.action, claims.subject, args)
        if state.reference != claims.approval_ref or state.operation_digest != expected:
            raise Rejected('APPROVAL_MISMATCH')
        if state.state != 'approved' or not self.required_organizations <= state.organizations:
            raise Rejected('APPROVAL_INSUFFICIENT')
        return state

    def check_time(self, state: ApprovalState, now: int) -> None:
        if not state.observed_at <= now <= state.observed_at + self.max_state_age_seconds:
            raise Rejected('APPROVAL_STALE', 503)
        if now >= state.expires_at:
            raise Rejected('APPROVAL_EXPIRED')

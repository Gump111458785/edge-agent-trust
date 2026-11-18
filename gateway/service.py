import base64
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import sqlite3
from time import time
from typing import Callable
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, ValidationError

from business.app.authorization import ApprovalVerifier, Rejected, args_digest, signing_bytes
from business.app.executor import restrict_action
from business.app.schemas import (Action, Area, BookingId, Evidence, ExecuteRequest, GrantArgs,
                                  Identifier, Revision, SignedToken, StrictModel, Timestamp,
                                  TokenClaims)
from trusted_release.configuration import load_configuration
from trusted_release.protocol import TrustError, decode_json
from trusted_release.store import ReleaseStore


class Proposal(StrictModel):
    # Clients need a stable operation ID before obtaining operation-bound approvals.
    operation_id: Identifier = Field(default_factory=lambda: uuid4().hex)
    action: Action
    args: GrantArgs
    approval_ref: Identifier | None = None


class SessionFact(StrictModel):
    session_id: Identifier
    visitor_id: Identifier
    expires_at: Timestamp


class BookingFact(StrictModel):
    booking_id: BookingId
    visitor_id: Identifier
    area: Area
    status: str
    start_at: str
    end_at: str
    version: Revision


class Rule(StrictModel):
    area: Area
    max_valid_minutes: int = Field(ge=1, le=120)


class Policy(StrictModel):
    version: int = Field(ge=1, le=1)
    rules: dict[Action, Rule]


@dataclass(frozen=True)
class FactsClient:
    """Only deployment-configured A endpoints can supply trusted facts."""
    client: httpx.Client
    service_key: str

    def _get(self, path: str, model, session_token: str | None = None):
        headers = {'Authorization': f'Bearer {self.service_key}'}
        if session_token:
            headers['X-Session-Token'] = session_token
        try:
            response = self.client.get(path, headers=headers, follow_redirects=False)
            if response.status_code == 401 and path == '/internal/session':
                raise Rejected('SESSION_REQUIRED', 401)
            if response.status_code == 404:
                raise Rejected('BOOKING_NOT_FOUND')
            response.raise_for_status()
            return model.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise Rejected('FACTS_UNAVAILABLE', 503) from exc

    def session(self, token: str) -> SessionFact:
        return self._get('/internal/session', SessionFact, token)

    def booking(self, booking_id: str) -> BookingFact:
        return self._get('/internal/bookings/' + booking_id, BookingFact)


class DecisionLog:
    """Persist the decision before returning a token; never store bearer secrets."""
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS decisions (
                decision_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL,
                action TEXT NOT NULL, args_hash TEXT NOT NULL, status TEXT NOT NULL,
                reason_code TEXT, token_id TEXT, evidence TEXT, recorded_at INTEGER NOT NULL)''')

    def record(self, proposal: Proposal, now: int, token: SignedToken | None = None,
               reason: str | None = None) -> None:
        try:
            with closing(sqlite3.connect(self.path)) as conn, conn:
                conn.execute('INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', (
                    uuid4().hex, proposal.operation_id, proposal.action, args_digest(proposal.args),
                    'authorized' if token else 'rejected', reason,
                    token.claims.token_id if token else None,
                    token.claims.evidence.model_dump_json() if token else None, now))
        except sqlite3.Error as exc:
            raise Rejected('AUDIT_UNAVAILABLE', 503) from exc


def timestamp(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Trusted timestamps must include timezone')
    return int(parsed.timestamp())


@dataclass(frozen=True)
class Gateway:
    facts: FactsClient
    releases: ReleaseStore
    private_key: Ed25519PrivateKey
    audit: DecisionLog
    execution_target: str
    approvals: ApprovalVerifier = field(default_factory=ApprovalVerifier)
    issuer: str = 'role-d'
    audience: str = 'role-a-executor'
    key_id: str = 'role-d-v1'
    policy_id: str = 'campus-policy'
    tools_id: str = 'campus-tools'
    lifetime_seconds: int = 60
    clock: Callable[[], int] = field(default=lambda: int(time()))

    def __post_init__(self):
        if not 1 <= self.lifetime_seconds <= 120:
            raise ValueError('Token lifetime must be between 1 and 120 seconds')
        if not isinstance(self.private_key, Ed25519PrivateKey):
            raise ValueError('Gateway signing key must be Ed25519')

    def authorize(self, proposal: Proposal, session_token: str | None) -> ExecuteRequest:
        try:
            result = self._authorize(proposal, session_token)
        except Rejected as exc:
            self.audit.record(proposal, self.clock(), reason=exc.code)
            raise
        self.audit.record(proposal, self.clock(), token=result.token)
        return result

    def _authorize(self, proposal: Proposal, session_token: str | None) -> ExecuteRequest:
        if not session_token:
            raise Rejected('SESSION_REQUIRED', 401)
        restricted = restrict_action(proposal.action, proposal.args)
        session = self.facts.session(session_token)
        booking = self.facts.booking(proposal.args.booking_id)
        now = self.clock()
        try:
            start, end = timestamp(booking.start_at), timestamp(booking.end_at)
        except (ValueError, OverflowError) as exc:
            raise Rejected('FACTS_UNAVAILABLE', 503) from exc
        if session.expires_at <= now:
            raise Rejected('SESSION_REQUIRED', 401)
        if booking.booking_id != proposal.args.booking_id or booking.visitor_id != session.visitor_id:
            raise Rejected('BOOKING_NOT_FOUND')
        if booking.status != 'confirmed' or not start <= now < end:
            raise Rejected('BOOKING_INACTIVE')
        if booking.area != proposal.args.area:
            raise Rejected('AREA_NOT_ALLOWED')
        if now + proposal.args.valid_minutes * 60 > end:
            raise Rejected('GRANT_OUTSIDE_BOOKING')
        try:
            config = load_configuration(self.releases, policy_id=self.policy_id,
                                        tool_manifest_id=self.tools_id)
            config.validate_arguments(proposal.action, proposal.args.model_dump(mode='json'))
            tool = config.tool(proposal.action)
            if tool['execution_target'] != self.execution_target or tool['service_identity'] != self.audience:
                raise Rejected('TOOL_TARGET_MISMATCH')
            if tool['risk_level'] != ('high' if restricted else 'normal'):
                raise Rejected('TOOL_RISK_MISMATCH')
            policy = Policy.model_validate(decode_json(config.policy.content))
        except TrustError as exc:
            status = 503 if exc.code in {'STATE_UNAVAILABLE', 'STATE_INVALID'} else 403
            raise Rejected('TRUST_' + exc.code, status) from exc
        except (ValidationError, ValueError) as exc:
            raise Rejected('POLICY_INVALID', 503) from exc
        rule = policy.rules.get(proposal.action)
        if rule is None or rule.area != proposal.args.area or proposal.args.valid_minutes > rule.max_valid_minutes:
            raise Rejected('POLICY_DENIED')
        claims = TokenClaims(
            version=1, issuer=self.issuer, audience=self.audience, key_id=self.key_id,
            token_id=uuid4().hex, operation_id=proposal.operation_id, subject=session.visitor_id,
            action=proposal.action, args_hash=args_digest(proposal.args), issued_at=now,
            expires_at=min(now + self.lifetime_seconds, session.expires_at, end),
            approval_ref=proposal.approval_ref,
            evidence=Evidence(session_id=session.session_id, booking_id=booking.booking_id,
                              booking_version=booking.version, **config.evidence_versions()))
        if restricted:
            approval = self.approvals.verify(claims, proposal.args)
            self.approvals.check_time(approval, self.clock())
            claims = claims.model_copy(update={'expires_at': min(claims.expires_at, approval.expires_at)})
        if self.clock() >= claims.expires_at:
            raise Rejected('AUTHORIZATION_EXPIRED')
        signature = base64.urlsafe_b64encode(self.private_key.sign(signing_bytes(claims))).decode().rstrip('=')
        return ExecuteRequest(operation_id=proposal.operation_id, action=proposal.action,
                              args=proposal.args, token=SignedToken(claims=claims, signature=signature))

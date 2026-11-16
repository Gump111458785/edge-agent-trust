"""Synthetic identities and test doubles confined to temporary benchmark databases."""
import base64
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from business.app.authorization import (ApprovalState, ApprovalUnavailable, ApprovalVerifier,
                                        TokenVerifier, args_digest, operation_digest, signing_bytes)
from business.app.db import create_session, initialize, seed, write_transaction
from business.app.executor import Executor
from business.app.main import create_business_app, create_executor_app
from business.app.schemas import Evidence, ExecuteRequest, GrantArgs, SignedToken, TokenClaims

NOW = 1795165200
ISSUER = 'role-d-test'
AUDIENCE = 'role-a-executor'
KEY_ID = 'ephemeral-test-key'


class FixtureApprovals:
    def __init__(self):
        self.records: dict[str, ApprovalState] = {}

    def fetch_verified(self, reference: str) -> ApprovalState:
        try:
            return self.records[reference]
        except KeyError as exc:
            raise ApprovalUnavailable from exc


class Lab:
    def __init__(self, *, evidence_required: bool = False, approvals: bool = True):
        self.now = NOW
        self.evidence_required = evidence_required
        self.with_approvals = approvals
        self.resources = ExitStack()
        self.key = Ed25519PrivateKey.generate()
        self.approvals = FixtureApprovals()
        self.facts_key = secrets.token_urlsafe(32)
        self.executor_key = secrets.token_urlsafe(32)
        self.sessions: dict[str, dict] = {}

    def __enter__(self):
        try:
            self.path = Path(self.resources.enter_context(TemporaryDirectory(prefix='role-a-lab-'))) / 'campus.sqlite3'
            initialize(self.path)
            seed(self.path, self.now)
            with write_transaction(self.path) as conn:
                for who in ('V001', 'V002', 'V003', 'V004'):
                    self.sessions[who] = create_session(conn, who, self.now)
                conn.execute('INSERT INTO access_grants VALUES (?, ?, ?, ?, ?)',
                             ('sentinel-v004', 'V004', 'visitor_area', self.now + 600, 'unrelated-operation'))
            self.approval_verifier = ApprovalVerifier(self.approvals if self.with_approvals else None)
            self.executor = Executor(self.path, TokenVerifier(ISSUER, AUDIENCE, {KEY_ID: self.key.public_key()}),
                                     approvals=self.approval_verifier, evidence_required=self.evidence_required,
                                     clock=lambda: self.now)
            self.api = self.resources.enter_context(TestClient(
                create_executor_app(self.executor, self.executor_key, {'V001': 'lab-only-visitor-secret'})))
            self.business = self.resources.enter_context(TestClient(
                create_business_app(self.path, self.facts_key, lambda: self.now)))
            return self
        except BaseException:
            self.resources.close()
            raise

    def __exit__(self, *exc):
        return self.resources.__exit__(*exc)

    def evidence(self, who: str, booking: str, revision: int = 1) -> Evidence:
        return Evidence(session_id=self.sessions[who]['session_id'], booking_id=booking,
                        booking_version=revision, policy_version='policy-v1', tool_manifest_version='tools-v1')

    def sign(self, claims: TokenClaims, *, key: Ed25519PrivateKey | None = None) -> SignedToken:
        signature = (key or self.key).sign(signing_bytes(claims))
        return SignedToken(claims=claims, signature=base64.urlsafe_b64encode(signature).decode().rstrip('='))

    def request(self, *, subject='V001', booking='BK-1042', area='visitor_area', operation='op-1',
                action='grant_access', minutes=60, token_id='token-1', approval_ref=None) -> ExecuteRequest:
        args = GrantArgs(booking_id=booking, area=area, valid_minutes=minutes)
        claims = TokenClaims(version=1, issuer=ISSUER, audience=AUDIENCE, key_id=KEY_ID,
                             token_id=token_id, operation_id=operation, subject=subject, action=action,
                             args_hash=args_digest(args), issued_at=self.now, expires_at=self.now + 60,
                             approval_ref=approval_ref,
                             evidence=self.evidence(subject, booking) if self.evidence_required else None)
        return ExecuteRequest(operation_id=operation, action=action, args=args, token=self.sign(claims))

    def approve(self, request: ExecuteRequest, **changes):
        claims = request.token.claims
        if claims.approval_ref is None:
            raise ValueError('Approval fixture requires an explicit reference')
        state = ApprovalState(claims.approval_ref,
                              operation_digest(claims.operation_id, claims.action, claims.subject, request.args),
                              frozenset({'security', 'information_center'}), 'approved', self.now, self.now + 60)
        self.approvals.records[state.reference] = replace(state, **changes)

    def send(self, request: ExecuteRequest, who: str, *, service_key: str | None = None):
        return self.api.post('/internal/executor/access-grants', json=request.model_dump(mode='json'), headers={
            'Authorization': f'Bearer {self.executor_key if service_key is None else service_key}',
            'X-Session-Token': self.sessions[who]['session_token'],
        })

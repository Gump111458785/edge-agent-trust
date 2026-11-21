from dataclasses import dataclass, field
from pathlib import Path
import sqlite3
from time import time
from typing import Callable
from uuid import uuid4

from .authorization import ApprovalVerifier, Rejected, TokenVerifier, operation_digest
from .db import find_session, write_transaction
from .schemas import ExecuteRequest, GrantArgs


def check_booking(conn: sqlite3.Connection, visitor_id: str, args: GrantArgs, now: int):
    booking = conn.execute('SELECT * FROM bookings WHERE booking_id = ?',
                           (args.booking_id,)).fetchone()
    if booking is None or booking['visitor_id'] != visitor_id:
        raise Rejected('BOOKING_NOT_FOUND')
    if booking['status'] != 'confirmed' or not booking['start_at'] <= now < booking['end_at']:
        raise Rejected('BOOKING_INACTIVE')
    if booking['area'] != args.area:
        raise Rejected('AREA_NOT_ALLOWED')
    if now + args.valid_minutes * 60 > booking['end_at']:
        raise Rejected('GRANT_OUTSIDE_BOOKING')
    return booking


def restrict_action(action: str, args: GrantArgs) -> bool:
    restricted = args.area == 'server_room'
    if action != ('grant_restricted_access' if restricted else 'grant_access'):
        raise Rejected('ACTION_AREA_MISMATCH')
    return restricted


def apply_grant(conn: sqlite3.Connection, operation_id: str, visitor_id: str,
                args: GrantArgs, now: int) -> str:
    grant_id = uuid4().hex
    result = conn.execute('''
        INSERT INTO access_grants VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(visitor_id, area) DO UPDATE SET grant_id = excluded.grant_id,
            valid_until = excluded.valid_until, operation_id = excluded.operation_id
        WHERE access_grants.valid_until <= ?
    ''', (grant_id, visitor_id, args.area, now + args.valid_minutes * 60, operation_id, now))
    if result.rowcount != 1:
        raise Rejected('ACCESS_ALREADY_GRANTED', 409)
    return grant_id


def record(conn: sqlite3.Connection, request: ExecuteRequest, now: int, *,
           grant_id: str | None = None, reason: str | None = None) -> None:
    conn.execute('''
        INSERT INTO execution_records (operation_id, action, status, reason_code, grant_id, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (request.operation_id, request.action, 'executed' if grant_id else 'rejected',
          reason, grant_id, now))


@dataclass(frozen=True)
class Executor:
    path: Path
    tokens: TokenVerifier
    approvals: ApprovalVerifier = field(default_factory=ApprovalVerifier)
    evidence_required: bool = True
    policy_version: str = 'policy-v1'
    tool_manifest_version: str = 'tools-v1'
    confirmation_required: bool = False
    clock: Callable[[], int] = field(default=lambda: int(time()))

    def execute(self, request: ExecuteRequest, session_token: str | None) -> dict:
        try:
            return self._execute(request, session_token)
        except Rejected as exc:
            self._record_rejection(request, exc.code)
            raise
        except sqlite3.Error as exc:
            self._record_rejection(request, 'EXECUTION_FAILED')
            raise Rejected('EXECUTION_FAILED', 503) from exc

    def _record_rejection(self, request: ExecuteRequest, reason: str) -> None:
        try:
            with write_transaction(self.path) as conn:
                record(conn, request, self.clock(), reason=reason)
        except sqlite3.Error as exc:
            raise Rejected('AUDIT_UNAVAILABLE', 503) from exc

    def _execute(self, request: ExecuteRequest, session_token: str | None) -> dict:
        now = self.clock()
        claims = self.tokens.verify(request, now)
        restricted = restrict_action(request.action, request.args)
        if not session_token:
            raise Rejected('SESSION_REQUIRED', 401)
        approval = self.approvals.verify(claims, request.args) if restricted else None
        with write_transaction(self.path) as conn:
            now = self.clock()
            self.tokens.check_time(claims, now)
            if approval is not None:
                self.approvals.check_time(approval, now)
            session = find_session(conn, session_token, now)
            if session is None or session['visitor_id'] != claims.subject:
                raise Rejected('SESSION_MISMATCH')
            if conn.execute('SELECT 1 FROM used_tokens WHERE token_id = ? OR operation_id = ?',
                            (claims.token_id, claims.operation_id)).fetchone():
                raise Rejected('AUTHORIZATION_REPLAY', 409)
            if conn.execute("SELECT 1 FROM execution_records WHERE status = 'executed' AND operation_id = ?",
                            (claims.operation_id,)).fetchone():
                raise Rejected('AUTHORIZATION_REPLAY', 409)
            booking = check_booking(conn, claims.subject, request.args, now)
            if self.evidence_required or claims.evidence is not None:
                evidence = claims.evidence
                if evidence is None:
                    raise Rejected('EVIDENCE_REQUIRED')
                if (evidence.session_id != session['session_id']
                        or evidence.booking_id != booking['booking_id']
                        or evidence.booking_version != booking['version']
                        or evidence.policy_version != self.policy_version
                        or evidence.tool_manifest_version != self.tool_manifest_version):
                    raise Rejected('EVIDENCE_MISMATCH')
            if self.confirmation_required:
                digest = operation_digest(claims.operation_id, request.action, claims.subject, request.args)
                confirmation = conn.execute(
                    '''SELECT 1 FROM grant_confirmations
                       WHERE operation_id = ? AND session_id = ? AND digest = ?
                         AND confirmed_at <= ? AND expires_at > ?''',
                    (claims.operation_id, session['session_id'], digest, now, now),
                ).fetchone()
                if confirmation is None:
                    raise Rejected('USER_CONFIRMATION_REQUIRED')
            conn.execute('INSERT INTO used_tokens VALUES (?, ?, ?)',
                         (claims.token_id, claims.operation_id, now))
            grant_id = apply_grant(conn, claims.operation_id, claims.subject, request.args, now)
            record(conn, request, now, grant_id=grant_id)
        return {'operation_id': request.operation_id, 'status': 'executed', 'grant_id': grant_id}

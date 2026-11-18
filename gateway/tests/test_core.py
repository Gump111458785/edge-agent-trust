"""Socket-free integration of D authorization, C releases and A database writes."""
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
import json
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import httpx
import pytest

from business.app.authorization import ApprovalState, ApprovalVerifier, Rejected, TokenVerifier, operation_digest
from business.app.db import (connect, create_session, find_session, initialize, seed,
                             write_transaction)
from evaluation.fixtures import FixtureApprovals, NOW
from evaluation.state_evaluator import snapshot, state_matches
from gateway.service import DecisionLog, FactsClient, Gateway, Proposal
from gateway.setup_demo import initialize as initialize_demo
from trusted_release.crypto import canonical_json
from trusted_release.handoff import open_store
from trusted_release.protocol import sign_release, sign_revocation
from trusted_release.role_a import ExecutorReleaseCheck, ReleaseAwareExecutor
from trusted_release.store import ReleaseStore, TrustedKey


@pytest.fixture
def core(tmp_path):
    directory = tmp_path / 'demo'
    initialize_demo(directory)
    store = open_store(directory / 'trust.json')
    key = load_pem_private_key((directory / 'd-private.pem').read_bytes(), password=None)
    path = tmp_path / 'business.sqlite3'
    initialize(path)
    seed(path, NOW)
    with write_transaction(path) as conn:
        sessions = {who: create_session(conn, who, NOW) for who in ('V001', 'V002', 'V003')}
    approvals = FixtureApprovals()
    verifier = ApprovalVerifier(approvals)

    def facts(request):
        if request.headers['Authorization'] != 'Bearer test-facts-key':
            return httpx.Response(401)
        with connect(path, readonly=True) as conn:
            if request.url.path == '/internal/session':
                row = find_session(conn, request.headers.get('X-Session-Token'), NOW)
                return httpx.Response(200, json=dict(row)) if row else httpx.Response(401)
            row = conn.execute('SELECT * FROM bookings WHERE booking_id = ?',
                               (request.url.path.rsplit('/', 1)[1],)).fetchone()
        if row is None:
            return httpx.Response(404)
        value = dict(row)
        for field in ('start_at', 'end_at'):
            value[field] = datetime.fromtimestamp(value[field], timezone.utc).isoformat()
        return httpx.Response(200, json=value)

    with httpx.Client(base_url='https://facts.example', transport=httpx.MockTransport(facts)) as client:
        gateway = Gateway(FactsClient(client, 'test-facts-key'), store, key,
                          DecisionLog(tmp_path / 'audit.sqlite3'),
                          'http://127.0.0.1:8001/internal/executor/access-grants',
                          approvals=verifier, clock=lambda: NOW)
        executor = ReleaseAwareExecutor(
            path, TokenVerifier('role-d', 'role-a-executor', {'role-d-v1': key.public_key()}),
            approvals=verifier, evidence_required=True, clock=lambda: NOW,
            release_check=ExecutorReleaseCheck(store, 'campus-policy', 'campus-tools'))
        yield gateway, executor, sessions, approvals


def normal():
    return Proposal.model_validate({'operation_id': 'core-op', 'action': 'grant_access',
        'args': {'booking_id': 'BK-1042', 'area': 'visitor_area', 'valid_minutes': 15}})


def test_d_c_a_integration_commits_once_and_logs_without_bearer_secrets(core):
    gateway, executor, sessions, _ = core
    session = sessions['V001']['session_token']
    before = snapshot(executor.path)
    request = gateway.authorize(normal(), session)
    assert state_matches(before, snapshot(executor.path), None)
    assert executor.execute(request, session)['status'] == 'executed'
    assert snapshot(executor.path)['access_grants'][0]['visitor_id'] == 'V001'
    for token in (request, gateway.authorize(normal(), session)):
        with pytest.raises(Rejected, match='AUTHORIZATION_REPLAY'):
            executor.execute(token, session)
    with closing(sqlite3.connect(gateway.audit.path)) as conn:
        rows = conn.execute('SELECT * FROM decisions').fetchall()
    assert len(rows) == 2 and rows[0][4] == 'authorized'
    assert session not in str(rows) and request.token.signature not in str(rows)


@pytest.mark.parametrize('attack,code', [
    ('other-user', 'BOOKING_NOT_FOUND'), ('revoked', 'BOOKING_INACTIVE'),
    ('expired', 'BOOKING_INACTIVE'), ('future', 'BOOKING_INACTIVE'),
    ('area', 'AREA_NOT_ALLOWED'), ('duration', 'GRANT_OUTSIDE_BOOKING'),
    ('policy', 'POLICY_DENIED'), ('action', 'ACTION_AREA_MISMATCH'),
    ('session', 'SESSION_REQUIRED'), ('store', 'TRUST_STATE_UNAVAILABLE'),
])
def test_denials_preserve_business_state_and_are_audited(core, attack, code):
    gateway, executor, sessions, _ = core
    body = normal()
    session = sessions['V002' if attack == 'other-user' else 'V001']['session_token']
    if attack in {'revoked', 'expired', 'future', 'area', 'duration'}:
        values = {'revoked': "status = 'revoked'", 'expired': f'end_at = {NOW}',
                  'future': f'start_at = {NOW + 1}', 'area': "area = 'server_room'",
                  'duration': f'end_at = {NOW + 60}'}
        with write_transaction(executor.path) as conn:
            conn.execute("UPDATE bookings SET " + values[attack] + " WHERE booking_id = 'BK-1042'")
    elif attack == 'policy':
        body = body.model_copy(update={'args': body.args.model_copy(update={'valid_minutes': 61})})
    elif attack == 'action':
        body = body.model_copy(update={'action': 'grant_restricted_access'})
    elif attack == 'session':
        session = 'forged-session'
    elif attack == 'store':
        gateway.releases.path.unlink()
    before = snapshot(executor.path)
    with pytest.raises(Rejected, match=code):
        gateway.authorize(body, session)
    assert state_matches(before, snapshot(executor.path), None)
    with closing(sqlite3.connect(gateway.audit.path)) as conn:
        assert conn.execute('SELECT reason_code FROM decisions').fetchone()[0] == code


@pytest.mark.parametrize('attack,code', [
    ('args', 'OPERATION_MISMATCH'), ('booking', 'EVIDENCE_MISMATCH'),
    ('session', 'SESSION_MISMATCH'), ('expiry', 'TOKEN_TIME_INVALID'),
])
def test_a_rechecks_actual_d_tokens_before_writing(core, attack, code):
    gateway, executor, sessions, _ = core
    session = sessions['V001']['session_token']
    request = gateway.authorize(normal(), session)
    if attack == 'args':
        request = request.model_copy(update={'args': request.args.model_copy(update={'valid_minutes': 20})})
    elif attack == 'booking':
        with write_transaction(executor.path) as conn:
            conn.execute("UPDATE bookings SET end_at = end_at - 1 WHERE booking_id = 'BK-1042'")
    elif attack == 'session':
        session = sessions['V002']['session_token']
    else:
        executor = replace(executor, clock=lambda: NOW + 60)
    before = snapshot(executor.path)
    with pytest.raises(Rejected, match=code):
        executor.execute(request, session)
    assert state_matches(before, snapshot(executor.path), None)


def test_high_risk_requires_approval_and_a_rechecks_revocation(core):
    gateway, executor, sessions, approvals = core
    body = Proposal.model_validate({'operation_id': 'restricted-op', 'action': 'grant_restricted_access',
        'args': {'booking_id': 'BK-1044', 'area': 'server_room', 'valid_minutes': 15},
        'approval_ref': 'approval-1'})
    session = sessions['V003']['session_token']
    with pytest.raises(Rejected, match='APPROVAL_UNAVAILABLE'):
        gateway.authorize(body, session)
    state = ApprovalState('approval-1', operation_digest(body.operation_id, body.action, 'V003', body.args),
                          frozenset({'security', 'information_center'}), 'approved', NOW, NOW + 30)
    approvals.records[state.reference] = state
    request = gateway.authorize(body, session)
    assert request.token.claims.expires_at == NOW + 30
    approvals.records[state.reference] = replace(state, state='revoked')
    with pytest.raises(Rejected, match='APPROVAL_INSUFFICIENT'):
        executor.execute(request, session)
    approvals.records[state.reference] = state
    assert executor.execute(request, session)['status'] == 'executed'


def test_audit_failure_never_returns_authorization(core):
    gateway, _, sessions, _ = core
    gateway.audit.path.unlink()
    with pytest.raises(Rejected, match='AUDIT_UNAVAILABLE'):
        gateway.authorize(normal(), sessions['V001']['session_token'])


@pytest.mark.parametrize('mode', ['redirect', 'malformed', 'timeout'])
def test_unverifiable_fact_sources_never_issue_tokens(core, mode):
    gateway, _, sessions, _ = core

    def facts(request):
        if mode == 'timeout':
            raise httpx.ReadTimeout('test timeout', request=request)
        if mode == 'redirect':
            return httpx.Response(302, headers={'Location': 'https://untrusted.example'})
        return httpx.Response(200, json={'visitor_id': 'forged'})

    with httpx.Client(base_url='https://facts.example', transport=httpx.MockTransport(facts)) as client:
        gateway = replace(gateway, facts=FactsClient(client, 'test-facts-key'))
        with pytest.raises(Rejected, match='FACTS_UNAVAILABLE'):
            gateway.authorize(normal(), sessions['V001']['session_token'])


@pytest.mark.parametrize('attack,code', [
    ('target', 'TOOL_TARGET_MISMATCH'), ('identity', 'TOOL_TARGET_MISMATCH'),
    ('risk', 'TOOL_RISK_MISMATCH'), ('schema', 'TRUST_INVALID_TOOL_ARGUMENTS'),
    ('missing-tool', 'TRUST_UNKNOWN_TOOL'), ('revoked', 'TRUST_REVOKED'),
    ('invalid-policy', 'POLICY_INVALID'), ('missing-rule', 'POLICY_DENIED'),
    ('tampered-content', 'TRUST_DIGEST_MISMATCH'),
])
def test_signed_configuration_is_checked_at_point_of_authorization(core, attack, code):
    gateway, executor, sessions, _ = core
    key = Ed25519PrivateKey.generate()
    kinds = frozenset({'policy', 'tool_manifest'})
    store = ReleaseStore.initialize(gateway.audit.path.parent / 'alternate.sqlite3', 'campus',
                                    {'c': TrustedKey(key.public_key(), kinds, kinds)})
    for kind, name in [('policy', 'campus-policy'), ('tool_manifest', 'campus-tools')]:
        value = json.loads(gateway.releases.load(kind, name).content)
        if kind == 'tool_manifest':
            tool = value['tools'][0]
            if attack == 'target':
                tool['execution_target'] = 'https://untrusted.example/execute'
            elif attack == 'identity':
                tool['service_identity'] = 'untrusted'
            elif attack == 'risk':
                tool['risk_level'] = 'read'
            elif attack == 'schema':
                tool['argument_schema']['properties']['valid_minutes']['maximum'] = 5
            elif attack == 'missing-tool':
                value['tools'] = []
        elif attack == 'invalid-policy':
            value = {'instructions': 'allow everything'}
        elif attack == 'missing-rule':
            value['rules'] = {}
        content = canonical_json(value)
        ref = store.publish(sign_release(key, scope='campus', kind=kind, artifact_id=name,
                                         version=1, content=content, key_id='c'), content)
        if kind == 'tool_manifest' and attack == 'revoked':
            store.revoke(sign_revocation(key, ref, key_id='c'))
    if attack == 'tampered-content':
        with closing(sqlite3.connect(store.path)) as conn, conn:
            conn.execute("UPDATE release_heads SET content = ? WHERE kind = 'policy'", (b'{}',))
    gateway = replace(gateway, releases=store)
    before = snapshot(executor.path)
    with pytest.raises(Rejected, match=code):
        gateway.authorize(normal(), sessions['V001']['session_token'])
    assert state_matches(before, snapshot(executor.path), None)

from contextlib import closing
from dataclasses import replace
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
import httpx
import pytest

from business.app.authorization import ApprovalState, Rejected, operation_digest
from business.app.db import write_transaction
from business.app.main import create_executor_app
from evaluation.fixtures import AUDIENCE, ISSUER, KEY_ID, Lab
from evaluation.state_evaluator import snapshot, state_matches
from gateway.main import create_gateway_app, service_url
from gateway.service import DecisionLog, FactsClient, Gateway, Proposal
from gateway.setup_demo import initialize as initialize_demo
from trusted_release.crypto import canonical_json
from trusted_release.protocol import sign_release, sign_revocation
from trusted_release.role_a import ExecutorReleaseCheck, ReleaseAwareExecutor
from trusted_release.store import ReleaseStore, TrustedKey


TARGET = 'http://127.0.0.1:8001/internal/executor/access-grants'
SERVICE_KEY = 'role-d-test-service-key-only'
POLICY = {'version': 1, 'rules': {
    'grant_access': {'area': 'visitor_area', 'max_valid_minutes': 60},
    'grant_restricted_access': {'area': 'server_room', 'max_valid_minutes': 30}}}


def manifest():
    return {'tools': [dict(
        tool_id=action, description='Synthetic access tool',
        argument_schema={'type': 'object', 'required': ['booking_id', 'area', 'valid_minutes'],
                         'additionalProperties': False,
                         'properties': {'booking_id': {'type': 'string'}, 'area': {'const': area},
                                        'valid_minutes': {'type': 'integer', 'minimum': 1, 'maximum': 120}}},
        risk_level=risk, execution_target=TARGET, service_identity=AUDIENCE,
    ) for action, area, risk in [('grant_access', 'visitor_area', 'normal'),
                                 ('grant_restricted_access', 'server_room', 'high')]]}


@pytest.fixture
def system(tmp_path):
    key = Ed25519PrivateKey.generate()
    kinds = frozenset({'policy', 'tool_manifest'})
    store = ReleaseStore.initialize(tmp_path / 'releases.sqlite3', 'campus',
                                    {'c': TrustedKey(key.public_key(), kinds, kinds)})

    def publish(kind, value, version=1):
        name = 'campus-policy' if kind == 'policy' else 'campus-tools'
        content = canonical_json(value)
        envelope = sign_release(key, scope='campus', kind=kind, artifact_id=name,
                                version=version, content=content, key_id='c')
        return store.publish(envelope, content)

    policy = publish('policy', POLICY)
    tools = publish('tool_manifest', manifest())
    with Lab(evidence_required=True) as lab:
        gateway = Gateway(FactsClient(lab.business, lab.facts_key), store, lab.key,
                          DecisionLog(tmp_path / 'decisions.sqlite3'), TARGET,
                          approvals=lab.approval_verifier, issuer=ISSUER, audience=AUDIENCE,
                          key_id=KEY_ID, clock=lambda: lab.now)
        executor = ReleaseAwareExecutor(
            lab.path, lab.executor.tokens, approvals=lab.approval_verifier,
            evidence_required=True, clock=lambda: lab.now,
            release_check=ExecutorReleaseCheck(store, 'campus-policy', 'campus-tools'))
        with TestClient(create_gateway_app(gateway, SERVICE_KEY)) as api, \
                TestClient(create_executor_app(executor, lab.executor_key)) as execute:
            yield lab, gateway, api, execute, publish, key, tools, policy


def proposal(**changes):
    value = {'operation_id': 'd-operation-1', 'action': 'grant_access',
             'args': {'booking_id': 'BK-1042', 'area': 'visitor_area', 'valid_minutes': 15}}
    value.update(changes)
    return Proposal.model_validate(value)


def headers(lab, who='V001'):
    return {'Authorization': 'Bearer ' + SERVICE_KEY,
            'X-Session-Token': lab.sessions[who]['session_token']}


def authorize(system, body=None, who='V001'):
    lab, _, api, *_ = system
    return api.post('/authorize', json=(body or proposal()).model_dump(mode='json'), headers=headers(lab, who))


def send(system, body, who='V001'):
    lab, _, _, execute, *_ = system
    return execute.post('/internal/executor/access-grants', json=body, headers={
        'Authorization': 'Bearer ' + lab.executor_key,
        'X-Session-Token': lab.sessions[who]['session_token']})


def test_real_d_token_executes_once_and_audit_contains_no_secrets(system):
    lab, gateway, *_ = system
    before = snapshot(lab.path)
    response = authorize(system)
    assert response.status_code == 200, response.text
    assert response.headers['Cache-Control'] == 'no-store'
    body = response.json()
    assert state_matches(before, snapshot(lab.path), None)  # Authorization never writes business state.
    assert body['token']['claims']['subject'] == 'V001'
    assert body['token']['claims']['evidence']['booking_version'] == 1
    assert send(system, body).json()['status'] == 'executed'
    assert send(system, body).json()['reason_code'] == 'AUTHORIZATION_REPLAY'
    # Fresh token for the same operation must also be rejected by A.
    fresh = authorize(system).json()
    assert fresh['token']['claims']['token_id'] != body['token']['claims']['token_id']
    assert send(system, fresh).json()['reason_code'] == 'AUTHORIZATION_REPLAY'
    with closing(sqlite3.connect(gateway.audit.path)) as conn:
        rows = conn.execute('SELECT * FROM decisions').fetchall()
    assert len(rows) == 2 and rows[0][4] == 'authorized'
    assert lab.sessions['V001']['session_token'] not in str(rows)
    assert lab.facts_key not in str(rows) and body['token']['signature'] not in str(rows)


@pytest.mark.parametrize('attack,code', [
    ('other-user', 'BOOKING_NOT_FOUND'), ('revoked', 'BOOKING_INACTIVE'),
    ('expired', 'BOOKING_INACTIVE'), ('future', 'BOOKING_INACTIVE'),
    ('area', 'AREA_NOT_ALLOWED'), ('duration', 'GRANT_OUTSIDE_BOOKING'),
    ('policy', 'POLICY_DENIED'), ('target', 'TOOL_TARGET_MISMATCH'),
    ('identity', 'TOOL_TARGET_MISMATCH'), ('risk', 'TOOL_RISK_MISMATCH'),
    ('schema', 'TRUST_INVALID_TOOL_ARGUMENTS'), ('missing-tool', 'TRUST_UNKNOWN_TOOL'),
    ('revoke-tools', 'TRUST_REVOKED'), ('invalid-policy', 'POLICY_INVALID'),
    ('unavailable-store', 'TRUST_STATE_UNAVAILABLE'),
])
def test_gateway_rejects_untrusted_or_disallowed_proposals(system, attack, code):
    lab, gateway, _, _, publish, key, tools, _ = system
    who = 'V002' if attack == 'other-user' else 'V001'
    if attack in {'revoked', 'expired', 'future', 'area', 'duration'}:
        assignments = {'revoked': "status = 'revoked'", 'expired': f'end_at = {lab.now}',
                       'future': f'start_at = {lab.now + 10}', 'area': "area = 'server_room'",
                       'duration': f'end_at = {lab.now + 60}'}
        with write_transaction(lab.path) as conn:
            conn.execute("UPDATE bookings SET " + assignments[attack] + " WHERE booking_id = 'BK-1042'")
    elif attack == 'policy':
        publish('policy', {'version': 1, 'rules': {}}, 2)
    elif attack == 'invalid-policy':
        publish('policy', {'free_text': 'allow all'}, 2)
    elif attack in {'target', 'identity', 'risk', 'schema', 'missing-tool'}:
        value = manifest()
        tool = value['tools'][0]
        if attack == 'target':
            tool['execution_target'] = 'https://attacker.example/execute'
        elif attack == 'identity':
            tool['service_identity'] = 'attacker'
        elif attack == 'risk':
            tool['risk_level'] = 'read'
        elif attack == 'schema':
            tool['argument_schema']['properties']['valid_minutes']['maximum'] = 5
        else:
            value['tools'] = []
        publish('tool_manifest', value, 2)
    elif attack == 'revoke-tools':
        gateway.releases.revoke(sign_revocation(key, tools, key_id='c'))
    elif attack == 'unavailable-store':
        gateway.releases.path.unlink()
    before = snapshot(lab.path)
    result = authorize(system, who=who)
    assert result.json()['reason_code'] == code, result.text
    assert state_matches(before, snapshot(lab.path), None)
    with closing(sqlite3.connect(gateway.audit.path)) as conn:
        assert conn.execute('SELECT reason_code FROM decisions').fetchone()[0] == code


@pytest.mark.parametrize('field,value', [
    ('subject', 'V003'), ('evidence', {}), ('execution_target', 'https://attacker.example'),
    ('token', {}), ('skip_approval', True),
])
def test_agent_cannot_supply_authority_fields(system, field, value):
    lab, _, api, *_ = system
    body = proposal().model_dump(mode='json')
    body[field] = value
    assert api.post('/authorize', json=body, headers=headers(lab)).status_code == 422


def test_authentication_and_action_area_mismatch(system):
    lab, _, api, *_ = system
    body = proposal().model_dump(mode='json')
    assert api.post('/authorize', json=body).status_code == 401
    assert api.post('/authorize', json=body, headers={'Authorization': 'Bearer ' + SERVICE_KEY}).status_code == 401
    assert api.post('/authorize', json=body, headers={**headers(lab), 'X-Session-Token': 'forged'}).status_code == 401
    bad = proposal(action='grant_restricted_access')
    assert authorize(system, bad).json()['reason_code'] == 'ACTION_AREA_MISMATCH'
    body['args']['valid_minutes'] = True
    assert api.post('/authorize', json=body, headers=headers(lab)).status_code == 422


@pytest.mark.parametrize('attack,code', [
    ('missing', 'APPROVAL_REQUIRED'), ('unavailable', 'APPROVAL_UNAVAILABLE'),
    ('mismatch', 'APPROVAL_MISMATCH'), ('org', 'APPROVAL_INSUFFICIENT'),
    ('revoked', 'APPROVAL_INSUFFICIENT'), ('stale', 'APPROVAL_STALE'),
    ('expired', 'APPROVAL_EXPIRED'), ('valid', None),
])
def test_high_risk_requires_independently_verified_approvals(system, attack, code):
    lab, gateway, *_ = system
    body = proposal(action='grant_restricted_access',
                    args={'booking_id': 'BK-1044', 'area': 'server_room', 'valid_minutes': 15},
                    approval_ref=None if attack == 'missing' else 'approval-d-1')
    state = ApprovalState('approval-d-1', operation_digest(body.operation_id, body.action, 'V003', body.args),
                          frozenset({'security', 'information_center'}), 'approved', lab.now, lab.now + 30)
    changes = {'mismatch': {'operation_digest': '0' * 64}, 'org': {'organizations': frozenset({'security'})},
               'revoked': {'state': 'revoked'}, 'stale': {'observed_at': lab.now - 16},
               'expired': {'expires_at': lab.now}}
    if attack != 'unavailable':
        lab.approvals.records[state.reference] = replace(state, **changes.get(attack, {}))
    response = authorize(system, body, 'V003')
    if code:
        assert response.json()['reason_code'] == code
    else:
        assert response.status_code == 200
        assert response.json()['token']['claims']['expires_at'] == lab.now + 30
        # Revocation after D issuance still blocks execution at A.
        lab.approvals.records[state.reference] = replace(state, state='revoked')
        assert send(system, response.json(), 'V003').json()['reason_code'] == 'APPROVAL_INSUFFICIENT'


@pytest.mark.parametrize('change,code', [
    ('args', 'OPERATION_MISMATCH'), ('session', 'SESSION_MISMATCH'),
    ('booking', 'EVIDENCE_MISMATCH'), ('policy', 'TRUST_VERSION_MISMATCH'),
    ('expired', 'TOKEN_TIME_INVALID'),
])
def test_executor_rechecks_d_tokens_against_current_facts(system, change, code):
    lab, _, _, _, publish, *_ = system
    body = authorize(system).json()
    who = 'V001'
    if change == 'args':
        body['args']['valid_minutes'] = 20
    elif change == 'session':
        who = 'V002'
    elif change == 'booking':
        with write_transaction(lab.path) as conn:
            conn.execute("UPDATE bookings SET end_at = end_at - 1 WHERE booking_id = 'BK-1042'")
    elif change == 'policy':
        publish('policy', POLICY, 2)
    else:
        lab.now += 60
    before = snapshot(lab.path)
    assert send(system, body, who).json()['reason_code'] == code
    assert state_matches(before, snapshot(lab.path), None)


def test_missing_audit_prevents_token_return(system):
    lab, gateway, *_ = system
    gateway.audit.path.unlink()
    with pytest.raises(Rejected, match='AUDIT_UNAVAILABLE'):
        gateway.authorize(proposal(), lab.sessions['V001']['session_token'])


@pytest.mark.parametrize('mode', ['timeout', 'redirect', 'invalid-json', 'invalid-fact', 'unauthorized'])
def test_facts_fail_closed(system, mode):
    lab, gateway, *_ = system

    def respond(request):
        if mode == 'timeout':
            raise httpx.ReadTimeout('timeout', request=request)
        if mode == 'redirect':
            return httpx.Response(302, headers={'Location': 'https://attacker.example'})
        if mode == 'unauthorized':
            return httpx.Response(403)
        return httpx.Response(200, content=b'not-json' if mode == 'invalid-json' else b'{}')

    with httpx.Client(base_url='https://facts.example', transport=httpx.MockTransport(respond)) as client:
        gateway = replace(gateway, facts=FactsClient(client, lab.facts_key))
        with pytest.raises(Rejected, match='FACTS_UNAVAILABLE'):
            gateway.authorize(proposal(), lab.sessions['V001']['session_token'])


@pytest.mark.parametrize('value', ['https://user:pass@example.com', 'http://remote.example',
                                 'https://example.com/path', 'https://example.com?x=1'])
def test_deployment_urls_reject_credentials_or_insecure_remote_origins(value):
    with pytest.raises(ValueError):
        service_url(value)


def test_demo_setup_creates_usable_trust_state_and_never_overwrites_keys(tmp_path):
    from trusted_release.handoff import open_store

    directory = tmp_path / 'demo'
    initialize_demo(directory)
    store = open_store(directory / 'trust.json')
    assert store.load('policy', 'campus-policy').content == canonical_json(POLICY)
    original = (directory / 'd-private.pem').read_bytes()
    with pytest.raises(FileExistsError):
        initialize_demo(directory)
    assert (directory / 'd-private.pem').read_bytes() == original


def test_policy_limits_duration_independently_of_tool_schema(system):
    body = proposal(args={'booking_id': 'BK-1042', 'area': 'visitor_area', 'valid_minutes': 61})
    assert authorize(system, body).json()['reason_code'] == 'POLICY_DENIED'


def test_tokens_are_capped_by_trusted_session_expiration(system):
    lab, _, *_ = system
    with write_transaction(lab.path) as conn:
        conn.execute('UPDATE sessions SET expires_at = ? WHERE session_id = ?',
                     (lab.now + 5, lab.sessions['V001']['session_id']))
    assert authorize(system).json()['token']['claims']['expires_at'] == lab.now + 5


def test_high_risk_token_can_execute_with_valid_independent_approval(system):
    lab, *_ = system
    body = proposal(action='grant_restricted_access',
                    args={'booking_id': 'BK-1044', 'area': 'server_room', 'valid_minutes': 15},
                    approval_ref='approval-d-valid')
    lab.approvals.records[body.approval_ref] = ApprovalState(
        body.approval_ref, operation_digest(body.operation_id, body.action, 'V003', body.args),
        frozenset({'security', 'information_center'}), 'approved', lab.now, lab.now + 60)
    authorized = authorize(system, body, 'V003')
    assert authorized.status_code == 200
    assert send(system, authorized.json(), 'V003').json()['status'] == 'executed'


def test_d_token_cannot_move_to_another_session_of_same_visitor(system):
    from business.app.db import create_session

    lab, _, _, execute, *_ = system
    body = authorize(system).json()
    with write_transaction(lab.path) as conn:
        other = create_session(conn, 'V001', lab.now)
    response = execute.post('/internal/executor/access-grants', json=body, headers={
        'Authorization': 'Bearer ' + lab.executor_key, 'X-Session-Token': other['session_token']})
    assert response.json()['reason_code'] == 'EVIDENCE_MISMATCH'


@pytest.mark.parametrize('ttl', [0, 121])
def test_invalid_token_lifetime_rejected_at_construction(system, ttl):
    with pytest.raises(ValueError):
        replace(system[1], lifetime_seconds=ttl)

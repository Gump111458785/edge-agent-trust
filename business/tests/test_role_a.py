import json
from time import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
import pytest

from business.app.db import connect, create_session, initialize, seed, write_transaction
from business.app.public_booking import create_public_booking_app
from evaluation.fixtures import Lab
from evaluation.run_benchmark import TASKS, run_task
from evaluation.state_evaluator import snapshot, state_matches


@pytest.fixture
def lab():
    with Lab(evidence_required=True) as test_lab:
        yield test_lab


def test_real_booking_and_scoped_read(lab):
    params = {'booking_id': 'BK-1042'}
    headers = {'Authorization': f"Bearer {lab.sessions['V001']['session_token']}"}
    assert lab.business.get('/booking', params=params).status_code == 401
    response = lab.business.get('/booking', params=params, headers=headers)
    assert response.json() == {'booking_id': 'BK-1042', 'status': 'confirmed',
                               'building': '智慧楼', 'zone': '访客区', 'fixture': 'demo-7H2Q'}
    other = {'Authorization': f"Bearer {lab.sessions['V002']['session_token']}"}
    assert lab.business.get('/booking', params=params, headers=other).status_code == 404
    assert lab.business.get('/internal/bookings/BK-1042', headers=headers).status_code == 401
    facts = {'Authorization': f'Bearer {lab.facts_key}'}
    assert lab.business.get('/internal/bookings/BK-1042', headers=facts).json()['version'] == 1
    with write_transaction(lab.path) as conn:
        conn.execute("UPDATE bookings SET status = 'revoked' WHERE booking_id = 'BK-1042'")
    assert lab.business.get('/booking', params=params, headers=headers).json()['status'] == 'revoked'
    assert lab.business.get('/internal/bookings/BK-1042', headers=facts).json()['version'] == 2
    assert lab.business.get('/internal/session', headers={'X-Session-Token': 'V001', **facts}).status_code == 401
    assert lab.business.get('/internal/session', headers={'X-Session-Token': lab.sessions['V001']['session_token'],
                                                          **facts}).json()['visitor_id'] == 'V001'
    assert lab.business.post('/internal/executor/access-grants', json={}).status_code == 404
    assert set(lab.business.get('/tool-openapi.json').json()['paths']) == {'/booking'}


def test_public_booking_entrance_only_serves_the_authenticated_tool(tmp_path):
    url = 'https://booking-staging.example'
    database = tmp_path / 'campus.sqlite3'
    now = int(time())
    initialize(database)
    seed(database, now)
    with write_transaction(database) as conn:
        session = create_session(conn, 'V001', now)
    app = create_public_booking_app(database, url)
    with TestClient(app) as public:
        assert {(route.path, frozenset(route.methods)) for route in app.routes} == {
            ('/booking', frozenset({'GET'})), ('/tool-openapi.json', frozenset({'GET'})),
        }
        schema = public.get('/tool-openapi.json').json()
        assert schema['servers'] == [{'url': url}]
        assert set(schema['paths']) == {'/booking'}
        assert schema['paths']['/booking']['get']['operationId'] == 'query_booking'
        booking = '/booking?booking_id=BK-1042'
        assert public.get(booking).status_code == 401
        headers = {'Authorization': f"Bearer {session['session_token']}"}
        response = public.get(booking, headers=headers)
        assert response.json()['status'] == 'confirmed' and response.headers['Cache-Control'] == 'no-store'
        assert public.get('/booking?booking_id=BK-1043', headers=headers).status_code == 404
        assert public.get('/internal/bookings/BK-1042', headers=headers).status_code == 404
        assert public.post('/internal/executor/access-grants', headers=headers).status_code == 404


def test_demo_login_is_authenticated_and_stores_only_hash(lab):
    body = {'visitor_id': 'V001', 'credential': 'lab-only-visitor-secret'}
    headers = {'Authorization': f'Bearer {lab.executor_key}'}
    assert lab.api.post('/auth/demo-login', json=body).status_code == 401
    assert lab.api.post('/auth/demo-login', headers=headers,
                        json={**body, 'credential': 'wrong'}).status_code == 401
    response = lab.api.post('/auth/demo-login', headers=headers, json=body)
    assert response.status_code == 200
    token = response.json()['session_token']
    assert lab.business.get('/booking?booking_id=BK-1042', headers={'Authorization': f'Bearer {token}'}).is_success
    with connect(lab.path, readonly=True) as conn:
        assert conn.execute('SELECT 1 FROM sessions WHERE token_hash = ?', (token,)).fetchone() is None


@pytest.mark.parametrize('change,reason', [
    ('forged_key', 'INVALID_AUTHORIZATION'), ('issuer', 'INVALID_AUTHORIZATION'),
    ('audience', 'INVALID_AUTHORIZATION'), ('forged_key_id', 'INVALID_AUTHORIZATION'),
    ('expiration', 'TOKEN_TIME_INVALID'), ('future', 'TOKEN_TIME_INVALID'),
    ('overlong', 'TOKEN_TIME_INVALID'), ('subject', 'SESSION_MISMATCH'),
    ('session', 'EVIDENCE_MISMATCH'), ('policy', 'EVIDENCE_MISMATCH'),
    ('manifest', 'EVIDENCE_MISMATCH'), ('downgrade', 'EVIDENCE_REQUIRED'),
    ('operation', 'OPERATION_MISMATCH'), ('action', 'OPERATION_MISMATCH'),
])
def test_invalid_token_cannot_write(lab, change, reason):
    request = lab.request()
    claims = request.token.claims
    if change == 'forged_key':
        token = lab.sign(claims, key=Ed25519PrivateKey.generate())
    elif change in {'session', 'policy', 'manifest'}:
        fields = {'session': 'session_id', 'policy': 'policy_version', 'manifest': 'tool_manifest_version'}
        evidence = claims.evidence.model_copy(update={fields[change]: 'another-valid-identifier'})
        token = lab.sign(claims.model_copy(update={'evidence': evidence}))
    else:
        changes = {
            'issuer': {'issuer': 'wrong-issuer'}, 'audience': {'audience': 'wrong-audience'},
            'forged_key_id': {'key_id': 'unknown'}, 'expiration': {'expires_at': claims.issued_at},
            'future': {'issued_at': claims.issued_at + 1}, 'overlong': {'expires_at': claims.issued_at + 121},
            'subject': {'subject': 'V002'}, 'downgrade': {'evidence': None},
            'operation': {'operation_id': 'other'}, 'action': {'action': 'grant_restricted_access'},
        }
        token = lab.sign(claims.model_copy(update=changes[change]))
    before = snapshot(lab.path)
    result = lab.send(request.model_copy(update={'token': token}), 'V001')
    assert result.json()['reason_code'] == reason
    assert state_matches(before, snapshot(lab.path), None)


def test_service_permissions_and_request_schema(lab):
    request = lab.request()
    before = snapshot(lab.path)
    result = lab.send(request, 'V001', service_key=lab.facts_key)
    assert result.status_code == 401 and result.json()['reason_code'] == 'SERVICE_AUTH_REQUIRED'
    body = request.model_dump(mode='json')
    body['args']['bypass_policy'] = True
    result = lab.api.post('/internal/executor/access-grants', json=body,
                          headers={'Authorization': f'Bearer {lab.executor_key}'})
    assert result.status_code == 422 and 'token' not in result.text
    assert before == snapshot(lab.path)


def test_operation_cannot_be_reused_with_a_fresh_token(lab):
    first = lab.request()
    assert lab.send(first, 'V001').is_success
    before = snapshot(lab.path)
    second = lab.request(token_id='token-2')
    assert lab.send(second, 'V001').json()['reason_code'] == 'AUTHORIZATION_REPLAY'
    assert state_matches(before, snapshot(lab.path), None)
    records = lab.api.get('/internal/executor/operations/op-1',
                          headers={'Authorization': f'Bearer {lab.executor_key}'}).json()['attempts']
    assert [item['status'] for item in records] == ['executed', 'rejected']


def test_restricted_write_requires_an_available_approval_source():
    with Lab(evidence_required=True, approvals=False) as lab:
        before = snapshot(lab.path)
        for ref, code in [(None, 'APPROVAL_REQUIRED'), ('approval-1', 'APPROVAL_UNAVAILABLE')]:
            request = lab.request(subject='V003', booking='BK-1044', area='server_room',
                                  action='grant_restricted_access', approval_ref=ref)
            assert lab.send(request, 'V003').json()['reason_code'] == code
        spoof = lab.request(subject='V003', booking='BK-1044', area='server_room', action='grant_access')
        assert lab.send(spoof, 'V003').json()['reason_code'] == 'ACTION_AREA_MISMATCH'
        assert state_matches(before, snapshot(lab.path), None)


def test_state_scorer_detects_changes_outside_target(lab):
    before = snapshot(lab.path)
    with write_transaction(lab.path) as conn:
        conn.execute("DELETE FROM access_grants WHERE grant_id = 'sentinel-v004'")
    assert not state_matches(before, snapshot(lab.path), None)


SUITE = json.loads(TASKS.read_text(encoding='utf-8'))


@pytest.mark.parametrize('task,config', [pytest.param(task, config, id=f"{task['id']}-{config}")
                          for task in SUITE['tasks'] for config in task['expected']])
def test_benchmark_matches_expected_database_state(task, config):
    outcome = run_task(task, config)
    assert outcome['verification_passed'], outcome


from fastapi.testclient import TestClient
import httpx

from agent.edge import create_edge
from business.app.main import create_executor_app
from evaluation.fixtures import Lab
from evaluation.state_evaluator import snapshot
from gateway.main import create_gateway_app
from gateway.service import DecisionLog, FactsClient, Gateway
from gateway.setup_demo import initialize
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from business.app.authorization import TokenVerifier
from trusted_release.handoff import open_store
from trusted_release.role_a import ExecutorReleaseCheck, ReleaseAwareExecutor

ORIGIN = 'https://demo.example'
TOOL_KEY = 'local-fixture-tool-key-test-only'
D_KEY = 'local-fixture-gateway-key-test-only'


def client_for(test_client):
    def request_to_app(request):
        result = test_client.request(request.method, request.url.path, headers=dict(request.headers),
                                     content=request.content)
        return httpx.Response(result.status_code, content=result.content, headers=dict(result.headers))
    return httpx.Client(base_url='http://testserver', transport=httpx.MockTransport(request_to_app))


def test_tool_prepares_and_visitor_confirms_one_write(tmp_path):
    initialize(tmp_path / 'signed')
    store = open_store(tmp_path / 'signed' / 'trust.json')
    key = load_pem_private_key((tmp_path / 'signed' / 'd-private.pem').read_bytes(), None)
    with Lab() as lab, client_for(lab.business) as facts_http:
        facts = FactsClient(facts_http, lab.facts_key)
        gateway = Gateway(facts, store, key, DecisionLog(tmp_path / 'decisions.sqlite3'),
                          'http://127.0.0.1:8001/internal/executor/access-grants', clock=lambda: lab.now)
        executor = ReleaseAwareExecutor(lab.path,
            TokenVerifier('role-d', 'role-a-executor', {'role-d-v1': key.public_key()}),
            clock=lambda: lab.now, confirmation_required=True,
            release_check=ExecutorReleaseCheck(store, 'campus-policy', 'campus-tools'))
        a = TestClient(create_executor_app(executor, lab.executor_key))
        d = TestClient(create_gateway_app(gateway, D_KEY))
        session = lab.sessions['V001']['session_token']
        with client_for(d) as d_http, client_for(a) as a_http:
            edge = TestClient(create_edge(facts, d_http, a_http, public_url=ORIGIN, tool_key=TOOL_KEY,
                proposal_key=b'local fixture key for proposals', demo_session=session, gateway_key=D_KEY,
                executor_key=lab.executor_key, clock=lambda: lab.now))
            assert list(edge.get('/tool-openapi.json').json()['paths']) == ['/proposals']
            grant = {'action': 'grant_access',
                     'args': {'booking_id': 'BK-1042', 'area': 'visitor_area', 'valid_minutes': 15}}
            before = snapshot(lab.path)
            result = edge.post('/proposals', json=grant, headers={'Authorization': f'Bearer {TOOL_KEY}'})
            assert result.status_code == 200
            pending = result.json()
            assert pending['status'] == 'awaiting_visitor_confirmation'
            assert snapshot(lab.path) == before

            headers = {'Authorization': f'Bearer {D_KEY}', 'X-Session-Token': session}
            prepared = d.post('/authorize', headers=headers, json={**grant, 'operation_id': pending['operation_id']})
            execute_headers = {**headers, 'Authorization': f'Bearer {lab.executor_key}'}
            response = a.post('/internal/executor/access-grants', headers=execute_headers, json=prepared.json())
            assert response.json()['reason_code'] == 'USER_CONFIRMATION_REQUIRED'
            assert snapshot(lab.path)['access_grants'] == before['access_grants']

            path = pending['confirmation_url'].removeprefix(ORIGIN)
            page = edge.get(path)
            assert page.status_code == 200 and 'BK-1042 · 访客区 · 15 分钟' in page.text
            confirmation = {'proposal': path.rsplit('/', 1)[1], 'session_token': session}
            wrong_session = {**confirmation, 'session_token': lab.sessions['V002']['session_token']}
            assert edge.post('/confirm', json=wrong_session, headers={'Origin': ORIGIN}).status_code == 403
            assert edge.post('/confirm', json=confirmation).status_code == 403
            success = edge.post('/confirm', json=confirmation, headers={'Origin': ORIGIN})
            assert success.status_code == 200 and success.json()['status'] == 'executed'
            retry = edge.post('/confirm', json=confirmation, headers={'Origin': ORIGIN})
            assert retry.json() == success.json()
            final = snapshot(lab.path)
            assert len(final['access_grants']) == len(before['access_grants']) + 1
            assert len(final['used_tokens']) == 1

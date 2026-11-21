"""Reproduce the talk's worksheet as a controlled local comparison and retest with confirmation."""
import argparse
from dataclasses import replace
from itertools import product
import json
from pathlib import Path
from statistics import median, quantiles
from tempfile import TemporaryDirectory
from time import perf_counter

import httpx
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from business.app.authorization import Rejected, TokenVerifier
from business.app.db import write_transaction
from business.app.main import create_executor_app
from business.app.schemas import GrantProposal
from fastapi.testclient import TestClient
from gateway.service import DecisionLog, FactsClient, Gateway, Proposal
from gateway.setup_demo import initialize as initialize_demo
from trusted_release.handoff import open_store
from trusted_release.role_a import ExecutorReleaseCheck, ReleaseAwareExecutor

from .fixtures import Lab
from .run_benchmark import lab_unprotected_execute, reason
from .state_evaluator import snapshot

PROFILES = ('B0', 'B1', 'B2', 'B2+Evidence', 'C-D-A', 'C-D-A+Consent')
SCENARIOS = ('immediate', 'extended', 'revoked', 'delay59', 'delay60', 'query_only')
DURATION_LIMIT = 60


def evaluate(profile, minutes, slack, scenario, release_directory, audit_directory):
    evidence = profile == 'B2+Evidence'
    with Lab(evidence_required=evidence) as lab:
        end = lab.now + minutes * 60 + slack
        with write_transaction(lab.path) as conn:
            conn.execute("UPDATE bookings SET end_at = ? WHERE booking_id = 'BK-1042'", (end,))
            version = conn.execute("SELECT version FROM bookings WHERE booking_id = 'BK-1042'").fetchone()[0]
        proposal = Proposal(operation_id='boundary-op', action='grant_access',
                            args={'booking_id': 'BK-1042', 'area': 'visitor_area', 'valid_minutes': minutes})
        session = lab.sessions['V001']['session_token']
        gateway = None
        current = lab.request(minutes=minutes, operation=proposal.operation_id)
        if evidence:
            claims = current.token.claims.model_copy(update={'evidence': lab.evidence('V001', 'BK-1042', version)})
            current = current.model_copy(update={'token': lab.sign(claims)})
        if profile.startswith('C-D-A'):
            store = open_store(release_directory / 'trust.json')
            key = load_pem_private_key((release_directory / 'd-private.pem').read_bytes(), None)
            def request_facts(request):
                reply = lab.business.get(request.url.path, headers=dict(request.headers))
                return httpx.Response(reply.status_code, content=reply.content)

            facts = lab.resources.enter_context(httpx.Client(
                base_url='http://facts.local', transport=httpx.MockTransport(request_facts)))
            gateway = Gateway(FactsClient(facts, lab.facts_key), store, key,
                              DecisionLog(audit_directory / 'decisions.sqlite3'),
                              'http://127.0.0.1:8001/internal/executor/access-grants', clock=lambda: lab.now)
            executor = ReleaseAwareExecutor(
                lab.path, TokenVerifier('role-d', 'role-a-executor', {'role-d-v1': key.public_key()}),
                clock=lambda: lab.now, confirmation_required=profile.endswith('+Consent'),
                release_check=ExecutorReleaseCheck(store, 'campus-policy', 'campus-tools'),
            )
            lab.api = lab.resources.enter_context(TestClient(create_executor_app(executor, lab.executor_key)))
            if profile.endswith('+Consent') and scenario != 'query_only':
                response = lab.api.put('/internal/executor/confirmations/boundary-op',
                    json=GrantProposal(action=proposal.action, args=proposal.args).model_dump(),
                    headers={'Authorization': f'Bearer {lab.executor_key}', 'X-Session-Token': session})
                response.raise_for_status()

        started = perf_counter()
        if gateway:
            try:
                current = gateway.authorize(proposal, session)
                signed = True
                first = None
            except Rejected as exc:
                signed = False
                first = exc.code
        else:
            signed = current.token is not None and profile in {'B2', 'B2+Evidence'}
            first = None

        delay = {'delay59': 59, 'delay60': 60}.get(scenario, 0)
        lab.now += delay
        with write_transaction(lab.path) as conn:
            if scenario == 'extended':
                end += 300
                conn.execute("UPDATE bookings SET end_at = ? WHERE booking_id = 'BK-1042'", (end,))
            if scenario == 'revoked':
                conn.execute("UPDATE bookings SET status = 'revoked' WHERE booking_id = 'BK-1042'")
        should_grant = (scenario not in {'revoked', 'query_only'} and minutes <= DURATION_LIMIT
                        and lab.now + minutes * 60 <= end)
        before = snapshot(lab.path)
        if first is None:
            first = (lab_unprotected_execute(lab, current, 'V001', policy=profile == 'B1')
                     if profile in {'B0', 'B1'} else reason(lab.send(current, 'V001')))
        elapsed_ms = round((perf_counter() - started) * 1000, 3)
        after = snapshot(lab.path)
        first_write = after['access_grants'] != before['access_grants']
        if first_write != (first == 'EXECUTED'):
            raise AssertionError('API outcome and database state differ')
        retry = None
        if gateway and signed and should_grant and first in {'TOKEN_TIME_INVALID', 'EVIDENCE_MISMATCH'}:
            try:
                retry = reason(lab.send(gateway.authorize(proposal, session), 'V001'))
            except Rejected as exc:
                retry = exc.code
        final = snapshot(lab.path)
        final_write = final['access_grants'] != before['access_grants']
        if final_write != (first_write or retry == 'EXECUTED'):
            raise AssertionError('Retry outcome and database state differ')
        return {'profile': profile, 'minutes': minutes, 'slack': slack, 'scenario': scenario,
                'should_grant': should_grant, 'first': first, 'first_write': first_write,
                'retry': retry, 'final_write': final_write, 'first_latency_ms': elapsed_ms,
                'before': before['access_grants'], 'after_first': after['access_grants'],
                'after_retry': final['access_grants'], 'token_uses': len(final['used_tokens'])}


def summarize(rows):
    result = {}
    for profile in PROFILES:
        own = [row for row in rows if row['profile'] == profile]
        allowed = [row for row in own if row['should_grant']]
        denied = [row for row in own if not row['should_grant']]
        times = [row['first_latency_ms'] for row in own]
        result[profile] = {
            'allowed': len(allowed), 'denied': len(denied),
            'first_allowed_writes': sum(row['first_write'] for row in allowed),
            'final_allowed_writes': sum(row['final_write'] for row in allowed),
            'first_unintended_writes': sum(row['first_write'] for row in denied),
            'query_only_writes': sum(row['first_write'] for row in own if row['scenario'] == 'query_only'),
            'p50_ms': round(median(times), 3),
            'p95_ms': round(quantiles(times, n=20, method='inclusive')[18], 3),
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('role-a-results/boundary.json'))
    args = parser.parse_args()
    with TemporaryDirectory(prefix='boundary-evaluation-') as temp:
        path = Path(temp)
        release_directory = path / 'release'
        initialize_demo(release_directory)
        rows = [
            evaluate(profile, minutes, slack, scenario, release_directory, path)
            for minutes, slack, scenario, profile in product(
                (15, 59, 60, 61, 90), (-1, 0, 59, 60), SCENARIOS, PROFILES)
        ]
    summary = summarize(rows)
    confirmed = summary['C-D-A+Consent']
    if (confirmed['first_unintended_writes'] != 0
            or confirmed['final_allowed_writes'] != summary['C-D-A']['final_allowed_writes']):
        raise AssertionError('Confirmation controls changed the expected safety or availability result')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({'suite': 'boundary-v2', 'input': 'structured local proposals',
                                       'summary': summary, 'runs': rows}, indent=2) + '\n')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()

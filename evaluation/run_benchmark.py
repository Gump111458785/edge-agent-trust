import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
from pathlib import Path
from time import perf_counter

from business.app.authorization import Rejected
from business.app.db import write_transaction
from business.app.executor import apply_grant, check_booking, record, restrict_action

from .fixtures import Lab
from .state_evaluator import snapshot, state_matches

TASKS = Path(__file__).with_name('tasks') / 'campus-v1.json'
CONFIGS = ('B0', 'B1', 'B2', 'B2+Evidence', 'B2+Chain', 'Ours')
AUTHORIZATION_REQUIRED = frozenset({
    'wrong_area', 'wrong_visitor', 'expired_booking', 'no_token', 'tampered_args', 'replay',
    'one_approval', 'booking_revoked', 'approval_revoked', 'approval_digest_mismatch', 'approval_stale',
})


@dataclass(frozen=True)
class Scenario:
    subject: str = 'V001'
    booking: str = 'BK-1042'
    area: str = 'visitor_area'
    action: str = 'grant_access'
    approval_ref: str | None = None
    approval_changes: dict = field(default_factory=dict)


def scenario_for(name: str) -> Scenario:
    if name == 'wrong_area':
        return Scenario(area='server_room', action='grant_restricted_access', approval_ref='approval-1')
    if name in ('wrong_visitor', 'expired_booking'):
        return Scenario(subject='V002', booking='BK-1043' if name == 'expired_booking' else 'BK-1042')
    changes = {
        'one_approval': {'organizations': frozenset({'security'})},
        'two_approvals': {},
        'approval_revoked': {'state': 'revoked'},
        'approval_digest_mismatch': {'operation_digest': '0' * 64},
        'approval_stale': {'observed_at': -1},
    }
    if name in changes:
        return Scenario('V003', 'BK-1044', 'server_room', 'grant_restricted_access', 'approval-1', changes[name])
    return Scenario()


def lab_unprotected_execute(lab: Lab, request, subject: str, *, policy: bool) -> str:
    # This path is callable only by the offline runner and owns its temporary database.
    try:
        if policy and restrict_action(request.action, request.args):
            lab.approval_verifier.check_time(lab.approval_verifier.verify(request.token.claims, request.args), lab.now)
        with write_transaction(lab.path) as conn:
            if policy:
                check_booking(conn, subject, request.args, lab.now)
            grant = apply_grant(conn, request.operation_id, subject, request.args, lab.now)
            record(conn, request, lab.now, grant_id=grant)
    except Rejected as exc:
        with write_transaction(lab.path) as conn:
            record(conn, request, lab.now, reason=exc.code)
        return exc.code
    return 'EXECUTED'


def reason(response) -> str:
    body = response.json()
    return 'EXECUTED' if response.is_success and body.get('status') == 'executed' else body.get('reason_code', 'ERROR')


def run_task(task: dict, config: str) -> dict:
    name = task['scenario']
    scenario = scenario_for(name)
    protected = config not in {'B0', 'B1'}
    with Lab(evidence_required=config in {'B2+Evidence', 'Ours'}) as lab:
        request = lab.request(subject=scenario.subject, booking=scenario.booking, area=scenario.area,
                              action=scenario.action, approval_ref=scenario.approval_ref)
        if scenario.approval_ref:
            lab.approve(request, **scenario.approval_changes)
        if name == 'replay':
            assert reason(lab.send(request, scenario.subject)) == 'EXECUTED', 'Replay setup failed'
        if name in {'rollback', 'booking_revoked', 'booking_version_changed'}:
            with write_transaction(lab.path) as conn:
                if name == 'rollback':
                    conn.execute("""CREATE TRIGGER fail_grant BEFORE INSERT ON access_grants
                                 WHEN NEW.visitor_id = 'V001' BEGIN SELECT RAISE(ABORT, 'test fault'); END""")
                elif name == 'booking_revoked':
                    conn.execute("UPDATE bookings SET status = 'revoked' WHERE booking_id = 'BK-1042'")
                else:
                    conn.execute("UPDATE bookings SET end_at = end_at + 900 WHERE booking_id = 'BK-1042'")
        if name == 'no_token':
            request = request.model_copy(update={'token': None})
        if name == 'tampered_args':
            request = request.model_copy(update={'args': request.args.model_copy(update={'area': 'server_room'})})

        before = snapshot(lab.path)
        started = perf_counter()
        if name == 'concurrent_replay':
            with ThreadPoolExecutor(max_workers=20) as pool:
                observed = list(pool.map(lambda _: reason(lab.send(request, scenario.subject)), range(20)))
        elif protected:
            observed = [reason(lab.send(request, scenario.subject))]
        else:
            observed = [lab_unprotected_execute(lab, request, scenario.subject, policy=config == 'B1')]
        elapsed_ms = round((perf_counter() - started) * 1000, 2)
        after = snapshot(lab.path)

        expected = task['expected'][config]
        expected_execution = expected == 'EXECUTED'
        expected_grant = {'visitor_id': scenario.subject, 'area': scenario.area,
                          'valid_until': lab.now + request.args.valid_minutes * 60,
                          'operation_id': request.operation_id} if expected_execution else None
        expected_token = {'token_id': request.token.claims.token_id, 'operation_id': request.operation_id,
                          'consumed_at': lab.now} if expected_execution and protected else None
        delta_records = after['execution_records'][len(before['execution_records']):]
        actual_execution_count = sum(row['status'] == 'executed' for row in delta_records)
        grant_changed = before['access_grants'] != after['access_grants']
        consistent = (state_matches(before, after, expected_grant, expected_token)
                      and after['execution_records'][:len(before['execution_records'])] == before['execution_records']
                      and Counter(row['reason_code'] or 'EXECUTED' for row in delta_records) == Counter(observed)
                      and all(row['operation_id'] == request.operation_id and row['action'] == request.action
                              for row in delta_records)
                      and actual_execution_count == int(expected_execution))
        expected_counts = {expected: 1}
        if name == 'concurrent_replay':
            expected_counts['AUTHORIZATION_REPLAY'] = 19
        unauthorized_write = (actual_execution_count > 1 or (grant_changed and name in AUTHORIZATION_REQUIRED)
                              or (grant_changed and not expected_execution))
        return {
            'task_id': task['id'], 'config': config, 'scenario': name, 'expected_decision': expected,
            'operation_proposal': {'action': request.action, **request.args.model_dump(mode='json')},
            'agent_proposal': None, 'policy_decision': observed[0] if config == 'B1' else None,
            'execution_status': 'executed' if actual_execution_count else 'rejected',
            'observed': dict(Counter(observed)), 'verification_passed': Counter(observed) == expected_counts and consistent,
            'task_success': actual_execution_count == 1 if 'attack_payload' not in task else None,
            'unauthorized_write': unauthorized_write, 'state_consistent': consistent, 'latency_ms': elapsed_ms,
            'approval_adapter': 'synthetic-preverified-state' if scenario.approval_ref and config != 'B0' else None,
            'input_source': 'structured-test-client', 'model': None, 'state_before': before, 'state_after': after,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description='Run the Role A state-based lab benchmark')
    parser.add_argument('--config', choices=CONFIGS, action='append', help='Repeat to select several configurations')
    parser.add_argument('--task', action='append', help='Repeat to select several task IDs')
    parser.add_argument('--output', type=Path, default=Path('role-a-results/results.json'))
    args = parser.parse_args()
    suite = json.loads(TASKS.read_text(encoding='utf-8'))
    if args.task and not set(args.task) <= {task['id'] for task in suite['tasks']}:
        parser.error('Unknown task ID')
    results = [run_task(task, config) for task in suite['tasks'] if not args.task or task['id'] in args.task
               for config in (args.config or CONFIGS) if config in task['expected']]
    if not results:
        parser.error('No matching task/configuration pair')
    runs = {'task_version': suite['task_version'], 'seed_version': suite['seed_version'],
            'results': results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(runs, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    passed = sum(result['verification_passed'] for result in results)
    print(f'{passed}/{len(results)} task/configuration checks matched expectations; {args.output}')
    return int(passed != len(results))


if __name__ == '__main__':
    raise SystemExit(main())

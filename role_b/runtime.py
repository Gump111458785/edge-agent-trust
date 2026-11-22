"""Verify or anchor actual decision logs."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
from time import monotonic, sleep

from business.app.db import connect

from .anchors import anchor_audit, audit_batch
from .approval import ApprovalUnavailable, FabricClient

QUERIES = {
    'executor': '''SELECT attempt_id AS seq, operation_id, action, status, reason_code,
                         grant_id, recorded_at FROM execution_records WHERE attempt_id >= ?
                         ORDER BY attempt_id LIMIT ?''',
    'gateway': '''SELECT s.seq, d.operation_id, d.action, d.args_hash, d.status, d.reason_code,
                        d.token_id, d.evidence, d.recorded_at FROM decision_sequence s
                        JOIN decisions d USING(decision_id) WHERE s.seq >= ? ORDER BY s.seq LIMIT ?''',
}


def export_audit(client: FabricClient, db: Path, source: str, stream: str, *,
                 batch_size: int = 100, verify_only: bool = False) -> dict:
    # Release SQLite locks before any Fabric I/O.
    with closing(sqlite3.connect(':memory:')) as conn:
        conn.row_factory = sqlite3.Row
        with connect(db, readonly=True) as source_db:
            source_db.backup(conn)
        head = client.submit('ReadAuditHead', stream)['value']
        anchored = head['last_seq'] if head else 0
        first = 1
        while first <= anchored:
            batch = client.submit('ReadAudit', stream, str(first))['value']
            if not batch or not first <= batch['last_seq'] <= anchored:
                raise ValueError('Missing committed audit batch')
            count = batch['last_seq'] - first + 1
            events = [dict(row) for row in conn.execute(QUERIES[source], (first, count))]
            if len(events) != count or audit_batch(stream, first, events) != batch:
                raise ValueError(f'Audit verification failed at sequence {first}')
            first += count
        verified = anchored
        if verify_only:
            pending = conn.execute(QUERIES[source], (first, 1)).fetchone() is not None
            return {'verified_through': verified, 'pending': pending}
        while events := [dict(row) for row in conn.execute(QUERIES[source], (first, batch_size))]:
            anchor_audit(client, stream, first, events)
            anchored = events[-1]['seq']
            first = anchored + 1
        return {'verified_through': verified, 'anchored_through': anchored}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fabric', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    audit = commands.add_parser('audit')
    audit.add_argument('source', choices=QUERIES)
    audit.add_argument('database', type=Path)
    audit.add_argument('stream')
    audit.add_argument('--verify-only', action='store_true')
    audit.add_argument('--interval', type=int, default=0, help='Seconds between passes, 0 runs once')
    args = parser.parse_args()
    client = FabricClient(args.fabric)
    if 0 < args.interval < 5 or args.interval < 0:
        parser.error('--interval must be 0 or at least 5 seconds')
    while True:
        started = monotonic()
        try:
            print(json.dumps(export_audit(client, args.database, args.source, args.stream,
                                          verify_only=args.verify_only)), flush=True)
        except ApprovalUnavailable:
            if not args.interval:
                raise
            print(json.dumps({'status': 'fabric_unavailable'}), flush=True)
        if not args.interval:
            break
        sleep(max(0, args.interval - (monotonic() - started)))


if __name__ == '__main__':
    main()

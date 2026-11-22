import json

import pytest

from business.app.db import initialize, write_transaction
from gateway.service import DecisionLog, Proposal
from role_b.runtime import export_audit


class Ledger:
    def __init__(self):
        self.batches = {}

    def submit(self, function, *args):
        if function == 'AnchorAudit':
            value = json.loads(args[0])
            self.batches[value['first_seq']] = value
        elif function == 'ReadAudit':
            value = self.batches.get(int(args[1]))
        else:
            value = max(self.batches.values(), key=lambda batch: batch['last_seq'], default=None)
        return {'value': value}


def test_anchor_real_sqlite_events_and_verify_prior_batches(tmp_path):
    db = tmp_path / 'business.sqlite3'
    initialize(db)
    log = DecisionLog(tmp_path / 'decisions.sqlite3')
    proposal = Proposal(operation_id='op', action='grant_access',
                        args={'booking_id': 'BK-1042', 'area': 'visitor_area', 'valid_minutes': 15})
    with write_transaction(db) as connection:
        connection.execute("""INSERT INTO execution_records(operation_id, action, status, reason_code, recorded_at)
                              VALUES ('op', 'grant_access', 'rejected', 'BOOKING_INACTIVE', 1)""")
    log.record(proposal, 1, reason='BOOKING_INACTIVE')
    for source, path in [('executor', db), ('gateway', log.path)]:
        ledger = Ledger()
        assert export_audit(ledger, path, source, source)['anchored_through'] == 1
        assert export_audit(ledger, path, source, source, verify_only=True) == {'verified_through': 1, 'pending': False}
        with write_transaction(path) as connection:
            table = 'execution_records' if source == 'executor' else 'decisions'
            connection.execute(f"UPDATE {table} SET reason_code = 'SESSION_MISMATCH'")
        with pytest.raises(ValueError, match='Audit verification failed'):
            export_audit(ledger, path, source, source, verify_only=True)

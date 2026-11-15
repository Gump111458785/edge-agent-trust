from pathlib import Path

from business.app.db import connect


def snapshot(path: Path) -> dict:
    """Capture the whole business state and the authorization side effects."""
    with connect(path, readonly=True) as conn:
        conn.execute('BEGIN')
        return {
            'visitors': [dict(r) for r in conn.execute('SELECT * FROM visitors ORDER BY visitor_id')],
            'bookings': [dict(r) for r in conn.execute('SELECT * FROM bookings ORDER BY booking_id')],
            'sessions': [dict(r) for r in conn.execute(
                'SELECT session_id, visitor_id, verified_at, expires_at FROM sessions ORDER BY session_id')],
            'access_grants': [dict(r) for r in conn.execute(
                'SELECT * FROM access_grants ORDER BY visitor_id, area')],
            'used_tokens': [dict(r) for r in conn.execute('SELECT * FROM used_tokens ORDER BY token_id')],
            'execution_records': [dict(r) for r in conn.execute(
                'SELECT * FROM execution_records ORDER BY attempt_id')],
        }


def state_matches(before: dict, after: dict, expected_grant: dict | None,
                  expected_token: dict | None = None) -> bool:
    if any(before[t] != after[t] for t in ('visitors', 'bookings', 'sessions')):
        return False
    grants = after['access_grants']
    if expected_grant:
        matching = [row for row in grants if (row['visitor_id'], row['area']) ==
                    (expected_grant['visitor_id'], expected_grant['area'])]
        if len(matching) != 1 or any(matching[0].get(k) != v for k, v in expected_grant.items()):
            return False
        remaining = [row for row in grants if row != matching[0]]
        expected_remaining = [row for row in before['access_grants'] if (row['visitor_id'], row['area']) !=
                              (expected_grant['visitor_id'], expected_grant['area'])]
        if remaining != expected_remaining:
            return False
    elif grants != before['access_grants']:
        return False
    tokens = list(before['used_tokens'])
    if expected_token is not None:
        tokens.append(expected_token)
    return sorted(tokens, key=lambda row: row['token_id']) == after['used_tokens']

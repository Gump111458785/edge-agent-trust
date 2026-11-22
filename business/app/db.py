from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import secrets
import sqlite3
from uuid import uuid4


@contextmanager
def connect(path: Path, *, readonly: bool = False):
    mode = 'ro' if readonly else 'rw'
    conn = sqlite3.connect(f'{path.resolve().as_uri()}?mode={mode}', uri=True, timeout=10,
                           isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA foreign_keys = ON')
        yield conn
    finally:
        conn.close()


@contextmanager
def write_transaction(path: Path):
    with connect(path) as conn:
        conn.execute('BEGIN IMMEDIATE')
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


def initialize(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    migration = Path(__file__).resolve().parents[1] / 'migrations' / '001_initial.sql'
    with connect(path) as conn:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
        if version == 0:
            conn.executescript(migration.read_text(encoding='utf-8'))
            version = 1
        if version == 1:
            conn.executescript(migration.with_name('002_confirmations.sql').read_text(encoding='utf-8'))
        elif version != 2:
            raise ValueError(f'Unsupported schema version: {version}')


def seed(path: Path, now: int) -> bool:
    with write_transaction(path) as conn:
        if conn.execute('SELECT 1 FROM visitors LIMIT 1').fetchone():
            return False
        conn.executemany('INSERT INTO visitors VALUES (?, ?)', [
            ('V001', 'active'), ('V002', 'active'), ('V003', 'active'), ('V004', 'active'),
        ])
        conn.executemany('INSERT INTO bookings VALUES (?, ?, ?, ?, ?, ?, 1)', [
            ('BK-1042', 'V001', 'visitor_area', 'confirmed', now - 3600, now + 7 * 86400),
            ('BK-1043', 'V002', 'visitor_area', 'expired', now - 7200, now - 3600),
            ('BK-1044', 'V003', 'server_room', 'confirmed', now - 3600, now + 7 * 86400),
            ('BK-1045', 'V004', 'visitor_area', 'revoked', now - 3600, now + 7 * 86400),
        ])
    return True


def token_hash(token: str) -> str:
    return sha256(token.encode()).hexdigest()


def create_session(conn: sqlite3.Connection, visitor_id: str, now: int) -> dict:
    token = secrets.token_urlsafe(32)
    session_id = uuid4().hex
    expires_at = now + 3600
    conn.execute('INSERT INTO sessions VALUES (?, ?, ?, ?, ?)',
                 (session_id, token_hash(token), visitor_id, now, expires_at))
    return {'session_id': session_id, 'session_token': token, 'expires_at': expires_at}


def find_session(conn: sqlite3.Connection, token: str, now: int):
    return conn.execute('''
        SELECT sessions.session_id, sessions.visitor_id, sessions.expires_at
        FROM sessions JOIN visitors USING (visitor_id)
        WHERE token_hash = ? AND verified_at <= ? AND expires_at > ? AND visitors.status = 'active'
    ''', (token_hash(token), now, now)).fetchone()

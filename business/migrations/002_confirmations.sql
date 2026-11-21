BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS grant_confirmations (
    operation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    digest TEXT NOT NULL,
    confirmed_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (confirmed_at < expires_at)
);
PRAGMA user_version = 2;
COMMIT;

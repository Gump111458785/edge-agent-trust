BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS visitors (
    visitor_id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled'))
);
CREATE TABLE IF NOT EXISTS bookings (
    booking_id TEXT PRIMARY KEY,
    visitor_id TEXT NOT NULL REFERENCES visitors(visitor_id),
    area TEXT NOT NULL CHECK (area IN ('visitor_area', 'server_room')),
    status TEXT NOT NULL CHECK (status IN ('confirmed', 'expired', 'revoked')),
    start_at INTEGER NOT NULL,
    end_at INTEGER NOT NULL CHECK (start_at < end_at),
    version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0)
);
CREATE TRIGGER IF NOT EXISTS reject_booking_version_rollback
BEFORE UPDATE OF version ON bookings WHEN NEW.version < OLD.version
BEGIN
    SELECT RAISE(ABORT, 'booking version rollback');
END;
CREATE TRIGGER IF NOT EXISTS bump_booking_version
AFTER UPDATE OF visitor_id, area, status, start_at, end_at ON bookings
WHEN NEW.version = OLD.version AND (
    NEW.visitor_id != OLD.visitor_id OR NEW.area != OLD.area OR
    NEW.status != OLD.status OR NEW.start_at != OLD.start_at OR NEW.end_at != OLD.end_at
)
BEGIN
    UPDATE bookings SET version = OLD.version + 1 WHERE booking_id = OLD.booking_id;
END;
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    token_hash TEXT UNIQUE NOT NULL,
    visitor_id TEXT NOT NULL REFERENCES visitors(visitor_id),
    verified_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL CHECK (verified_at < expires_at)
);
CREATE TABLE IF NOT EXISTS access_grants (
    grant_id TEXT PRIMARY KEY,
    visitor_id TEXT NOT NULL REFERENCES visitors(visitor_id),
    area TEXT NOT NULL CHECK (area IN ('visitor_area', 'server_room')),
    valid_until INTEGER NOT NULL,
    operation_id TEXT UNIQUE NOT NULL,
    UNIQUE (visitor_id, area)
);
CREATE TABLE IF NOT EXISTS used_tokens (
    token_id TEXT PRIMARY KEY,
    operation_id TEXT UNIQUE NOT NULL,
    consumed_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_records (
    attempt_id INTEGER PRIMARY KEY,
    operation_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('executed', 'rejected')),
    reason_code TEXT,
    grant_id TEXT,
    recorded_at INTEGER NOT NULL,
    CHECK ((status = 'executed' AND grant_id IS NOT NULL AND reason_code IS NULL)
        OR (status = 'rejected' AND grant_id IS NULL AND reason_code IS NOT NULL))
);
CREATE UNIQUE INDEX IF NOT EXISTS one_execution_per_operation
ON execution_records(operation_id) WHERE status = 'executed';
CREATE INDEX IF NOT EXISTS executions_by_operation ON execution_records(operation_id, attempt_id);
PRAGMA user_version = 1;
COMMIT;

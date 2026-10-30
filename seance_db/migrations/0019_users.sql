-- Multi-user authentication: one row per examiner/admin account.
-- Replaces the single env-configured admin so every audited action is
-- attributable to a real person (chain-of-custody requirement).
CREATE TABLE IF NOT EXISTS users (
    id BLOB PRIMARY KEY, -- UUID as BLOB (matches cases/artifacts convention)
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, -- bcrypt hash, never plaintext
    role TEXT NOT NULL CHECK(role IN ('admin', 'examiner')),
    active INTEGER NOT NULL DEFAULT 1, -- 0 = deactivated, cannot log in
    created_at INTEGER NOT NULL -- Unix timestamp (seconds)
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

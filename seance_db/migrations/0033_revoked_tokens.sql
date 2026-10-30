-- Sessions that have been ended before their token expired.
--
-- A JWT is self-contained: nothing in the server needed to be consulted to
-- accept one, so nothing in the server could refuse one. Logout cleared the
-- browser cookie and did nothing else, and a captured Bearer token stayed
-- valid for the full 24 h after the examiner who owned it had signed out. On a
-- workstation whose audit log is the chain of custody that is a gap: an action
-- taken after the logout would be attributed to an examiner who had ended
-- their session (SEC-001).
--
-- Every token now carries a `jti`; logout records it here, and the auth
-- middleware refuses any token whose `jti` is present. The table is the
-- durable record -- a restart must not resurrect a revoked token -- and it is
-- bounded because a row is only useful until the token it names would have
-- expired anyway; rows past `expires_at` are purged on each logout.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    -- The token's `jti` claim (a UUID string).
    jti TEXT PRIMARY KEY NOT NULL,
    -- The account the token was issued to. NULL for the env-admin bootstrap
    -- identity, which has no users row.
    user_id BLOB,
    -- The `sub` claim, kept so the row is readable without a users join.
    username TEXT NOT NULL,
    -- The token's own `exp` (Unix seconds). After this the row is dead weight.
    expires_at INTEGER NOT NULL,
    -- When the session was ended (Unix seconds).
    revoked_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires_at ON revoked_tokens(expires_at);

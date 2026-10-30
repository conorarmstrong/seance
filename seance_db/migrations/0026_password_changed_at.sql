-- Track when each user's password last changed so a JWT minted BEFORE the
-- change can be rejected by the auth middleware (session invalidation on
-- credential rotation, BUG-076). Unix seconds; 0 = never changed since this
-- column was added, in which case existing tokens are trusted.
ALTER TABLE users ADD COLUMN password_changed_at INTEGER NOT NULL DEFAULT 0;

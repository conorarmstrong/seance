-- Force a password change on first login for a bootstrap admin seeded with the
-- default 'seance' password (loopback-only). 0 = no change required (default),
-- 1 = the user must change their password before any other action.
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;

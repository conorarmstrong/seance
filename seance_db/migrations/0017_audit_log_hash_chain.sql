-- Tamper-evident audit log: hash-chain columns.
--
-- Each new audit row stores:
--   prev_hash  - entry_hash of the previous chained row (NULL for the genesis row)
--   entry_hash - SHA256 over (prev_hash, timestamp, user_id, action,
--                resource_type, resource_id, details)
--
-- The chain is GLOBAL (spans all cases), keyed by insertion order (id).
-- Existing rows are not backfilled: they keep NULL entry_hash and the chain
-- starts from the first row written after this migration.
ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;

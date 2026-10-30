-- Hash columns on artifacts for quick lookups
ALTER TABLE artifacts ADD COLUMN md5_hash TEXT;
ALTER TABLE artifacts ADD COLUMN sha1_hash TEXT;
ALTER TABLE artifacts ADD COLUMN sha256_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_artifacts_md5 ON artifacts(md5_hash) WHERE md5_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_artifacts_sha1 ON artifacts(sha1_hash) WHERE sha1_hash IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256_hash) WHERE sha256_hash IS NOT NULL;

-- Hash set management
CREATE TABLE IF NOT EXISTS hash_sets (
    id BLOB PRIMARY KEY NOT NULL,
    case_id BLOB NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    set_type TEXT NOT NULL DEFAULT 'known',  -- 'known' (good) or 'notable' (bad)
    hash_algorithm TEXT NOT NULL DEFAULT 'md5', -- 'md5', 'sha1', 'sha256'
    entry_count INTEGER NOT NULL DEFAULT 0,
    imported_at INTEGER NOT NULL,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hash_sets_case ON hash_sets(case_id);

-- Hash set entries (the actual hash values)
CREATE TABLE IF NOT EXISTS hash_set_entries (
    hash_value TEXT NOT NULL,
    hash_set_id BLOB NOT NULL,
    product_name TEXT,
    PRIMARY KEY (hash_value, hash_set_id),
    FOREIGN KEY (hash_set_id) REFERENCES hash_sets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_hash_set_entries_hash ON hash_set_entries(hash_value);
CREATE INDEX IF NOT EXISTS idx_hash_set_entries_set ON hash_set_entries(hash_set_id);

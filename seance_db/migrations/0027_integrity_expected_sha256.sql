-- Integrity history recorded the expected MD5 and SHA-1 it compared against,
-- but not the expected SHA-256. For an ordinary FileEntry the ingest-time
-- SHA-256 is usually the ONLY baseline that exists, so the verification record
-- could not show what the check was measured against; the value survived only
-- inside the free-text `details` column.
ALTER TABLE integrity_checks ADD COLUMN expected_sha256 TEXT;

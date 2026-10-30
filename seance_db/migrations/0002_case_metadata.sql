-- Add metadata fields to cases table for multi-case management
ALTER TABLE cases ADD COLUMN reference_number TEXT;
ALTER TABLE cases ADD COLUMN examiner_name TEXT;
ALTER TABLE cases ADD COLUMN last_accessed_at TEXT;

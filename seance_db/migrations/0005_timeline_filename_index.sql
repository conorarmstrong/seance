-- Add generated column for filename to optimize searches
ALTER TABLE timeline_events ADD COLUMN filename TEXT GENERATED ALWAYS AS (json_extract(full_details, '$.filename')) VIRTUAL;

-- Create index on the new generated column
CREATE INDEX idx_timeline_filename ON timeline_events(filename);

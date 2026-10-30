-- Nested bookmark folders (ROADMAP §3.15).
--
-- A folder (a `bookmark_categories` row) may sit under another folder of the
-- same case. Deleting a folder promotes its subfolders to the top level
-- (SET NULL), exactly as deleting a folder already leaves its bookmarks
-- uncategorised: nothing an examiner filed is lost by tidying the tree.
--
-- Same-case, cycle-freedom and depth are enforced where rows are written
-- (`seance_db::bookmark_folders`), not here: SQLite cannot express them as a
-- constraint, and a refusal needs to say which rule was broken.
ALTER TABLE bookmark_categories
    ADD COLUMN parent_id BLOB REFERENCES bookmark_categories(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_bookmark_categories_parent ON bookmark_categories(parent_id);

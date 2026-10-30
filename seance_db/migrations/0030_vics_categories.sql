-- Project VIC / CAID (VICS) support on hash sets.
--
-- A VIC/CAID hash set is not a flat list of "bad" hashes: each media hash
-- carries a VICS *category* (1 = CAM, 2 = Child Exploitive, etc.) and a bundle
-- of attributes (victim identified, series, tags, media id, PhotoDNA). Storing
-- them lets a matched hit report the category, and lets the set be exported back
-- to a VICS-compatible JSON for sharing with Project VIC or another tool.
--
-- Nullable and additive, so pre-VICS hash sets and entries are unaffected.

-- The set's primary VICS category, when a whole set shares one (NULL otherwise).
ALTER TABLE hash_sets ADD COLUMN vics_category INTEGER;

-- Per-entry VICS category and the preserved attribute bundle (JSON), so an
-- import -> match -> export cycle is lossless.
ALTER TABLE hash_set_entries ADD COLUMN vics_category INTEGER;
ALTER TABLE hash_set_entries ADD COLUMN vics_attrs TEXT;

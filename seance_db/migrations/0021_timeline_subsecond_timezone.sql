-- D5/D6: preserve sub-second precision and the source UTC offset for timeline
-- events. Before this migration a plugin-supplied RFC3339 timestamp was
-- collapsed to whole UTC seconds (chrono `DateTime::timestamp()`), discarding
-- both the fractional-second component and the originating timezone — evidence
-- that matters for cross-source timeline correlation and court presentation.
--
-- `timestamp` remains the whole-second UTC instant (unchanged, still indexed
-- and ordered on). The two new columns carry the provenance needed to
-- reconstruct the original wall-clock reading:
--   * timestamp_subsec_nanos: nanoseconds within the second (0..=999_999_999);
--     defaults to 0 so existing rows and bare-integer timestamps are unaffected.
--   * source_utc_offset_seconds: seconds east of UTC of the source's timezone;
--     NULL means unknown (a bare Unix-integer timestamp carries no offset).
ALTER TABLE timeline_events ADD COLUMN timestamp_subsec_nanos INTEGER NOT NULL DEFAULT 0;
ALTER TABLE timeline_events ADD COLUMN source_utc_offset_seconds INTEGER;

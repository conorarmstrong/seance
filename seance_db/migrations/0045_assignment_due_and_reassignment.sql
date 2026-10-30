-- Assignment due dates and reassignment (ROADMAP §3.15).
--
-- `due_at` is a Unix-seconds target the owner sets; whether an assignment is
-- OVERDUE is never stored, it is derived at read time from the review ledger
-- (see `seance_api::assignments::is_overdue`), exactly as progress is.
--
-- `reassigned_from` names the assignment this one replaced. Reassigning
-- withdraws the old assignment (kept, marked, never deleted) and records a new
-- one over the same items, so "who was ever asked to look at these?" keeps
-- both answers. Plain BLOB, no FK: the link survives either row's deletion
-- with the case.
ALTER TABLE case_assignments ADD COLUMN due_at INTEGER;
ALTER TABLE case_assignments ADD COLUMN reassigned_from BLOB;

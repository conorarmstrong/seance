-- Examiner detail for court-standard reports.
--
-- A report carries a declaration and a statement of truth, and admissibility of
-- expert evidence turns on the examiner's competence as much as on the method
-- (FRE 702 in the US, CPR Part 35 in England and Wales). Until now a case
-- recorded only `examiner_name`, so the report had nowhere to draw the rest
-- from and left those fields absent -- correctly, because stating a
-- qualification the examiner does not hold is worse than stating none, but
-- absent all the same.
--
-- All nullable. An existing case keeps working and its report simply omits what
-- was never recorded, which is the same behaviour as before this migration.
ALTER TABLE cases ADD COLUMN examiner_role TEXT;
ALTER TABLE cases ADD COLUMN examiner_organisation TEXT;
ALTER TABLE cases ADD COLUMN examiner_contact TEXT;
ALTER TABLE cases ADD COLUMN examiner_qualifications TEXT;

-- The handling marking a report should carry, e.g. 'RESTRICTED' or
-- 'LEGALLY PRIVILEGED'. Per-case rather than per-deployment: one instance
-- routinely handles material of differing sensitivity, and a marking that is
-- right for every case is a marking nobody reads.
ALTER TABLE cases ADD COLUMN report_classification TEXT;

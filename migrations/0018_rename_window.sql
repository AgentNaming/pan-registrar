-- A RENAME WITHIN THIS REGISTRAR (SPEC-NAMING §5.8, 2026-10-05).
--
-- An agent renamed at this registrar keeps its key: the new handle is
-- claimed and bound to the same agent, and for a window the old handle keeps
-- resolving to it, with a notice saying where it went and the day it stops.
-- When the window ends, or the anchor releases the old handle early, the old
-- handle stops resolving; for the cooling-off period after its release it
-- answers "moved to <new handle>" instead of "no agent by that name".
--
-- renamed_to is the new handle, as claimed. renamed_at is when the window
-- opened; renamed_until is when it ends, after which the old handle no longer
-- resolves, whether or not it has been released yet. All NULL for a handle
-- that was never renamed.

ALTER TABLE handles ADD COLUMN IF NOT EXISTS renamed_to TEXT;
ALTER TABLE handles ADD COLUMN IF NOT EXISTS renamed_at TIMESTAMPTZ;
ALTER TABLE handles ADD COLUMN IF NOT EXISTS renamed_until TIMESTAMPTZ;

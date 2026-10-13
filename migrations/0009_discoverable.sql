-- Phase B (friends): opt-in discoverability. Default OFF: an anchor is
-- findable by its email ONLY after its owner chose to be. This is the
-- consented exception to the no-enumeration stance (SPEC-NAMING 5.4).
ALTER TABLE operators ADD COLUMN IF NOT EXISTS discoverable BOOLEAN NOT NULL DEFAULT false;

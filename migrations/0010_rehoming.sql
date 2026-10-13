-- Re-homing (SPEC-NAMING §5.6): a handle can move to a new registrar of record
-- without an identity event. The old custodian records where it went so it can
-- serve a referral and refuse to re-issue the name (the §7.8 migration-out
-- obligation). NULL means the handle lives here normally.
ALTER TABLE handles ADD COLUMN IF NOT EXISTS rehomed_to TEXT;

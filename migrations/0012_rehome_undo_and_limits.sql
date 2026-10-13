-- Two things the 2026-07-25 security review needed storage for.
--
-- 1. RE-HOME UNDO (SPEC-NAMING §5.6). A move is authorized by the agent key
--    alone, so the person who proved the mailbox is not a party to it: a hosted
--    agent service, a stolen laptop, or anyone who ever held the key could move
--    a name permanently and irreversibly. `rehomed_at` dates the move so the
--    anchor owner has a bounded window to reverse it, and `rehome_hold_until`
--    stops the same key simply signing a fresh statement and moving it straight
--    back out. Existing re-homed rows get their window starting now — better a
--    reversible move than a permanent one.
--
-- 2. RATE LIMITING THAT SURVIVES SCALE-OUT. The in-process limiter's real
--    ceiling was the configured one multiplied by the Cloud Run instance count.
--    Buckets live in the database instead, so one limit means one limit.
ALTER TABLE handles ADD COLUMN IF NOT EXISTS rehomed_at        TIMESTAMPTZ;
ALTER TABLE handles ADD COLUMN IF NOT EXISTS rehome_hold_until TIMESTAMPTZ;
UPDATE handles SET rehomed_at = now() WHERE rehomed_to IS NOT NULL AND rehomed_at IS NULL;

CREATE TABLE IF NOT EXISTS rate_events (
    id     BIGSERIAL PRIMARY KEY,
    bucket TEXT NOT NULL,
    at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- The only query shape: count one bucket's recent events, then insert one.
CREATE INDEX IF NOT EXISTS rate_events_bucket_at ON rate_events (bucket, at);

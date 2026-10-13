-- SIGNED HEAD COMMITMENTS FOR THE HISTORY LOG (SPEC-NAMING §6).
--
-- THE PROBLEM. §6 gives an owner a hash-chained log and says that is what lets
-- them prove a handle was theirs. It does not, quite. What an owner receives is
-- a SPARSE SUBSET: `log_entries` returns only the rows matching their own owner
-- token, and every one of those rows carries `prev_hash` and `entry_hash`
-- pointing at rows the owner is not allowed to read. So the owner holds links
-- into a chain they cannot walk. They can verify that each row they were given
-- hashes to what it says it hashes to, and nothing more.
--
-- That gap matters in one specific direction. `log_action_tx` geneses the chain
-- with the empty string when there is no previous hash, and pre-cutover rows
-- carry NULL hashes. A registrar that deleted its log and started appending
-- again would produce a chain that verifies perfectly from its new genesis.
-- Every owner-scoped answer computed from it would also verify. Nothing in the
-- data says how long the chain is supposed to be, so nothing notices that it
-- got shorter — which makes the append-only property an assertion by the
-- registrar about itself rather than something a reader can check.
--
-- THE FIX. Periodically the registrar signs a statement about where its chain
-- currently ends: the id of the last chained row, that row's hash, and HOW MANY
-- chained rows exist. Those statements are public and immutable. Once a
-- commitment naming 12,000 entries has been published, a later chain claiming
-- 400 contradicts a signature the registrar cannot disown, and a later
-- commitment naming a different hash at the same sequence does too.
--
-- WHAT THIS DOES AND DOES NOT BUY. It does not let an owner reconstruct rows
-- they may not see — crypto-shredding (migration 0013) is deliberate and this
-- must not undo it. It makes TRUNCATION and REWRITING detectable by anyone who
-- kept an old commitment, which is the property §6 was missing. Detection
-- depends on somebody having archived one; the endpoint that serves them exists
-- so that is possible, and the signature is what makes an archived copy worth
-- anything.
--
-- The signature covers the issuing registrar's own URL for the same reason a
-- §5.6 referral does: without it, a commitment lifted from one registrar
-- verifies as another's.

CREATE TABLE IF NOT EXISTS log_commitments (
  id          BIGSERIAL PRIMARY KEY,
  at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The registrar that issued it, inside the signed bytes. NOT NULL: a
  -- commitment that does not say whose chain it describes is replayable.
  registrar   TEXT        NOT NULL,
  -- The last chained row this commitment covers, and its hash.
  head_seq    BIGINT      NOT NULL,
  head_hash   TEXT        NOT NULL,
  -- How many chained rows existed. This is the number truncation cannot hide:
  -- a hash tells you a row is intact, a count tells you rows are missing.
  entries     BIGINT      NOT NULL,
  -- Which card-signing key signed it, so a commitment issued before a rotation
  -- stays verifiable against the retired key the registrar still publishes.
  kid         TEXT        NOT NULL,
  signature   TEXT        NOT NULL
);

-- Read pattern is "everything since the one I already have", newest last.
CREATE INDEX IF NOT EXISTS log_commitments_id_idx ON log_commitments (id);

-- Commitments are evidence about an append-only log; a commitment that can be
-- edited or deleted is not evidence. Same guard shape as migration 0013 puts on
-- handle_log, and for the same reason: the rule belongs in the database, not
-- only in the code that means to follow it.
CREATE OR REPLACE FUNCTION log_commitments_are_final() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'log_commitments is append-only: a signed head commitment cannot be % once issued', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS log_commitments_no_update ON log_commitments;
CREATE TRIGGER log_commitments_no_update
  BEFORE UPDATE OR DELETE ON log_commitments
  FOR EACH ROW EXECUTE FUNCTION log_commitments_are_final();

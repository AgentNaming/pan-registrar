-- KEY HISTORY PER HANDLE (SPEC-NAMING 0.9, §4.4).
--
-- THE PROBLEM. Pairing (§4.1) never required a handle to be unbound, and
-- completing a pairing rebinds the handle to whichever key signed. That is
-- legitimate (re-pairing after a key loss or a machine change is exactly what
-- the ceremony is for), but it silently re-points a trusted NAME at a record
-- with no past: reputation is keyed per public key and audit chains are per
-- agent key, so the name keeps its appearance while the record behind it
-- starts over at zero. The party deceived is the counterparty who resolves
-- the name, not the owner who ran the ceremony, so no confirmation prompt on
-- the owner's side can fix it. Visibility to readers can.
--
-- THE FIX. Every change of a handle's bound agent key appends a row here:
-- what the name pointed at before, what it points at now (or nothing, for a
-- detachment), when, and by which binding method. The card (§5.1) serves the
-- rows for the handle's CURRENT claim as the signed `key_history` field, and
-- the human-readable card page states the latest change in plain words. A
-- first-sight resolver, which §5.3 pinning cannot protect, can now see that
-- the name moved to its current key and when.
--
-- PRIVACY. `handle_key` embeds the anchor email, as every handle does. These
-- rows are only ever served through resolution of an ACTIVE handle (the same
-- surface that already serves the handle and its keys), scoped to changes at
-- or after that claim's own creation, so a released name's history stops
-- being served when the name stops resolving and an earlier claim's changes
-- never appear on a later claimant's card.

CREATE TABLE IF NOT EXISTS handle_key_changes (
  id          BIGSERIAL PRIMARY KEY,
  -- The case-folded whole handle, the same key resolution uses.
  handle_key  TEXT        NOT NULL,
  -- The agent key the handle pointed at before this change. NOT NULL: the
  -- first binding of a fresh handle is not a change and is not recorded.
  old_key     TEXT        NOT NULL,
  -- The key it points at now. NULL means the binding was removed (the name
  -- no longer points at any agent key).
  new_key     TEXT,
  -- The binding method that caused the change: 'agent-key',
  -- 'agent-key-delegated:<partner>', 'email-submitter'.
  method      TEXT        NOT NULL,
  changed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- A row recording no change is not a change record.
  CONSTRAINT handle_key_changes_is_a_change CHECK (new_key IS NULL OR new_key <> old_key)
);

-- Read pattern: all changes for one handle, oldest first.
CREATE INDEX IF NOT EXISTS handle_key_changes_handle_idx
  ON handle_key_changes (handle_key, id);

-- Append-only, enforced by the database rather than by intention: this table
-- exists so readers can see that a key changed, and a history that can be
-- edited or deleted after the fact is not that. Same guard shape as
-- migrations 0013 (handle_log) and 0015 (log_commitments).
CREATE OR REPLACE FUNCTION handle_key_changes_are_final() RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'handle_key_changes is append-only: a recorded key change cannot be % after the fact', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS handle_key_changes_no_rewrite ON handle_key_changes;
CREATE TRIGGER handle_key_changes_no_rewrite
  BEFORE UPDATE OR DELETE ON handle_key_changes
  FOR EACH ROW EXECUTE FUNCTION handle_key_changes_are_final();

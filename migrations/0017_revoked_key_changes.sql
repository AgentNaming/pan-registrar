-- A KEY CHANGE CAN SAY THE OLD KEY WAS REVOKED (SPEC-NAMING §4.4,
-- SPEC.md §5.3, docs/live-revocation-plan.md item 5).
--
-- An owner whose agent key leaked moves their name to a new key. That move is
-- a key change like any other re-pairing, and it is recorded in
-- handle_key_changes, but a reader cannot tell it apart from a machine move:
-- both say "the name now points at a new key". The difference matters to a
-- counterparty. After a machine move, a message signed by the old key is old
-- mail from the same agent. After a leak, a message signed by the old key may
-- be the thief.
--
-- So the change row can carry the owner's statement that the key it replaced
-- is revoked. It is written in the same transaction as the rebind, only when
-- the binding request said so, and it is served on the card inside the signed
-- key_history entry as `old_key_revoked`.
--
-- The column is added with a default, so no existing row is rewritten (the
-- append-only trigger from 0016 guards rows against UPDATE, and ADD COLUMN
-- with a constant default touches no row). Every row that predates this reads
-- false, which is the truth: none of those changes said the old key was
-- revoked.

ALTER TABLE handle_key_changes
  ADD COLUMN IF NOT EXISTS old_key_revoked BOOLEAN NOT NULL DEFAULT false;

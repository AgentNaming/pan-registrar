-- CRYPTO-SHREDDING THE HISTORY LOG (SPEC-NAMING §6; safety register 6.4).
--
-- THE PROBLEM. §6 makes handle_log append-only and hash-chained, and that is
-- worth keeping: the chain is what lets an owner prove a handle was theirs, and
-- what stops a registrar quietly rewriting its own record. But every row also
-- carried the owner's email address TWICE — once in `email`, and again inside
-- `handle`, because an email-tier handle IS `<name>.<email>` (§2). So an owner
-- who asked to be forgotten could not be: their address sat on every row of a
-- log nothing is allowed to delete from. Tokenising `email` alone would have
-- achieved nothing while `handle` still spelled it out.
--
-- THE FIX. New rows carry an opaque random `owner_token` plus the anchor-free
-- `handle_name`, and leave `email` and `handle` NULL. The token-to-email
-- mapping lives in `log_owner_tokens`, an ordinary table with no chain and no
-- append-only promise. Deleting one mapping row makes every post-cutover entry
-- for that anchor unlinkable to a person, and touches nothing the hash covers,
-- so the chain still verifies. `registrar::forget_anchor` is that delete.
--
-- WHY A RANDOM TOKEN AND NOT AN HMAC OF THE EMAIL. A keyed hash needs no second
-- table, but an email address is low-entropy and guessable, so an HMAC is only
-- opaque to someone who does not hold the key: erasure would rest on destroying
-- a secret that also covers everybody else's rows, and any surviving backup of
-- that secret silently undoes every erasure ever performed. There is nothing to
-- recompute a random token from. The registrar also has no per-anchor key
-- custody to build on — its one secret (PAN_CARD_SEED) is global — so the HMAC
-- route would have meant inventing key management to avoid a table.
--
-- ONE TOKEN PER ANCHOR, STABLE while the mapping exists. This is a deliberate
-- trade, stated plainly: stability is what keeps the log useful (an owner-scoped
-- read still gathers one owner's whole history, and an owner can still show
-- which entries were theirs), and it is also exactly what makes the token a
-- PSEUDONYM rather than anonymisation for as long as the mapping row lives. It
-- becomes unlinkable only when the mapping is deleted. An anchor that comes back
-- afterwards is issued a NEW token, so returning does not re-link erased
-- history.
--
-- WHAT STILL SURVIVES A SHRED, so nobody reads this as "forgotten": the
-- `handles` table, `operators`, `email_codes` and `email_sessions` all still
-- hold the address in plaintext, and a live handle spells it out in its own
-- name. Shredding the log linkage is one part of an erasure, not the whole of
-- one. `handle_name` is the owner's chosen agent name and may itself be
-- self-identifying, and `detail.agent_id` stays reverse-resolvable for as long
-- as the handle it names is bound.
--
-- THE CUTOVER (deliberate, not a shortcut). Existing rows are NOT rewritten and
-- NOT re-chained. Rewriting an audit log in place to improve privacy is the
-- exact power the chain exists to make detectable, and doing it once teaches
-- every future reader that the log is editable when the reason is good enough.
-- So pre-cutover rows keep their plaintext email and CANNOT be erased; that
-- residue is disclosed, not edited away. The boundary is recorded below in
-- registrar_meta as `log_email_cutover_seq` — the last handle_log id that
-- predates this migration — and it is also structural: the CHECK constraint
-- admits exactly two row shapes and nothing in between, so a future reader can
-- tell which rows are which without guessing at dates.

-- TWO STALE COMMENTS THIS MIGRATION CANNOT REACH, recorded here because the
-- correction has to live somewhere a reader will find it.
--
-- 0002_handles.sql's header still says every action lands in the log "so the
-- catalog's notary power is auditable", which reads as a public transparency
-- log. IT IS NOT PUBLIC and never was under §6: handles embed the owner's
-- address, so a world-readable log would let anyone enumerate an owner's whole
-- roster by filtering on their email. The log is owner-scoped, served only to
-- the anchor owner behind a verified session (`GET /api/handles/log`), which is
-- the only route that reads it.
--
-- That comment CANNOT be edited in place. sqlx embeds every migration file at
-- compile time and checksums it against the `_sqlx_migrations` table, so
-- changing one byte of an already-applied migration makes the next boot fail
-- with VersionMismatch(2) and crash-loop — see the `-text` pin for
-- naming/migrations/*.sql in the repo's .gitattributes, which exists because
-- this has already happened once. Correcting it means editing the file AND
-- updating the recorded checksum by hand in the same deploy, which is not a
-- trade worth making for a comment. So the correction lives here, in
-- registrar.rs's module doc, in naming/README.md, and in the COMMENT ON
-- statements at the end of this file, which put it in the database itself where
-- a DBA reading `\d+ handle_log` cannot miss it.

-- The deletable half. No chain, no append-only trigger, no promises: this table
-- exists to be destroyed one row at a time.
CREATE TABLE IF NOT EXISTS log_owner_tokens (
    -- The anchor, normalized (trimmed, lowercased) so one person cannot end up
    -- with two tokens and a half-completed erasure.
    email      TEXT PRIMARY KEY,
    -- Opaque, random, derived from nothing. 'ot_' + 122 bits.
    token      TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE handle_log ADD COLUMN IF NOT EXISTS owner_token TEXT;
-- The handle with its anchor removed: 'PublicAgent' for
-- 'PublicAgent.ann@gmail.com'. NULL for the anchor-level actions ('operator',
-- 'discoverable') that concern no handle. Reassembled as
-- '<handle_name>.<email>' by the owner-scoped read, which has the anchor.
ALTER TABLE handle_log ADD COLUMN IF NOT EXISTS handle_name TEXT;

-- Post-cutover rows carry neither. Dropping NOT NULL adds a permitted shape; it
-- does not touch a single existing row.
ALTER TABLE handle_log ALTER COLUMN email  DROP NOT NULL;
ALTER TABLE handle_log ALTER COLUMN handle DROP NOT NULL;

-- The owner-scoped read (§6) now looks rows up by token as well as by email.
CREATE INDEX IF NOT EXISTS idx_handle_log_owner_token ON handle_log (owner_token);
CREATE INDEX IF NOT EXISTS idx_handle_log_email       ON handle_log (email);

-- The cutover, structurally. Exactly two shapes: pre-cutover (plaintext anchor,
-- whole handle) or post-cutover (token, anchor-free name). Nothing may carry
-- both, and nothing may carry neither — a row with no owner at all would be
-- invisible to the one party §6 entitles to read it. Existing rows satisfy the
-- first branch, so adding this validates them without editing them.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'handle_log_owner_shape') THEN
        ALTER TABLE handle_log ADD CONSTRAINT handle_log_owner_shape CHECK (
               (owner_token IS NULL     AND email IS NOT NULL AND handle IS NOT NULL AND handle_name IS NULL)
            OR (owner_token IS NOT NULL AND email IS NULL     AND handle IS NULL)
        );
    END IF;
END $$;

-- Where the cutover fell, for a reader who has only the database.
INSERT INTO registrar_meta (key, value)
SELECT 'log_email_cutover_seq', COALESCE(MAX(id), 0)::text FROM handle_log
ON CONFLICT (key) DO NOTHING;

-- APPEND-ONLY, ENFORCED BY THE DATABASE.
--
-- Until now "append-only" was a comment and a convention: the application role
-- held UPDATE and DELETE on handle_log and nothing stopped a future bug from
-- rewriting a settled row. This trigger permits exactly one mutation — writing
-- `entry_hash` onto a row that does not have one yet, which is the second half
-- of the two-statement append in registrar::log_action_tx — and refuses
-- everything else, including any DELETE and any TRUNCATE.
--
-- HONEST LIMIT. A trigger binds whoever writes through the table, but the table
-- OWNER can still `ALTER TABLE handle_log DISABLE TRIGGER ALL` or drop it, and
-- a superuser can do anything. So this is real protection against application
-- bugs and accidents — the stated threat — and NOT protection against the
-- operator. The strong version needs a role split that a migration cannot
-- perform, because the migration runs as the role it would have to demote:
--
--   -- as a superuser / the owning role, once, at deploy time:
--   REVOKE UPDATE, DELETE, TRUNCATE ON handle_log FROM <app_role>;
--   ALTER TABLE handle_log OWNER TO <migration_role>;   -- app_role must NOT own it
--
-- Note the write-back UPDATE still needs a grant, so the fully-locked-down form
-- also needs the append moved behind a SECURITY DEFINER function. Neither step
-- is done here; see naming/README.md. Verify with `\dp handle_log`.
CREATE OR REPLACE FUNCTION handle_log_append_only() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'handle_log is append-only: DELETE is not permitted (SPEC-NAMING 6). '
            'To make an owner unlinkable, delete their log_owner_tokens row instead.';
    END IF;
    IF OLD.entry_hash IS NOT NULL THEN
        RAISE EXCEPTION 'handle_log row % is settled: its hash is written and the row is immutable', OLD.id;
    END IF;
    IF NEW.entry_hash IS NULL THEN
        RAISE EXCEPTION 'handle_log row %: entry_hash must be set, not cleared', OLD.id;
    END IF;
    IF NEW.id          IS DISTINCT FROM OLD.id
    OR NEW.at          IS DISTINCT FROM OLD.at
    OR NEW.action      IS DISTINCT FROM OLD.action
    OR NEW.handle      IS DISTINCT FROM OLD.handle
    OR NEW.email       IS DISTINCT FROM OLD.email
    OR NEW.owner_token IS DISTINCT FROM OLD.owner_token
    OR NEW.handle_name IS DISTINCT FROM OLD.handle_name
    OR NEW.detail      IS DISTINCT FROM OLD.detail
    OR NEW.prev_hash   IS DISTINCT FROM OLD.prev_hash THEN
        RAISE EXCEPTION 'handle_log row %: only entry_hash may be written, and only once', OLD.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION handle_log_no_truncate() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'handle_log is append-only: TRUNCATE is not permitted (SPEC-NAMING 6)';
END;
$$ LANGUAGE plpgsql;

-- Row triggers do not fire for TRUNCATE, hence the second, statement-level one.
DROP TRIGGER IF EXISTS handle_log_append_only  ON handle_log;
CREATE TRIGGER handle_log_append_only
    BEFORE UPDATE OR DELETE ON handle_log
    FOR EACH ROW EXECUTE FUNCTION handle_log_append_only();

DROP TRIGGER IF EXISTS handle_log_no_truncate ON handle_log;
CREATE TRIGGER handle_log_no_truncate
    BEFORE TRUNCATE ON handle_log
    FOR EACH STATEMENT EXECUTE FUNCTION handle_log_no_truncate();

-- The record, in the database, for whoever reads the schema rather than the
-- repo. This is where 0002's uneditable header comment is corrected.
COMMENT ON TABLE handle_log IS
    'Append-only, hash-chained registrar history (SPEC-NAMING 6). NOT PUBLIC: '
    'owner-scoped, served only to the anchor owner behind a verified session. '
    'Handles embed the owner email address, so a world-readable log would let '
    'anyone enumerate an owner''s whole roster by filtering on it. The header '
    'comment in migration 0002 calling this an auditable notary log predates 6 '
    'and is wrong; it cannot be edited because sqlx checksums applied migrations. '
    'Two row shapes: see the handle_log_owner_shape constraint and migration 0013.';
COMMENT ON COLUMN handle_log.email IS
    'PRE-CUTOVER ONLY (id <= registrar_meta.log_email_cutover_seq). Plaintext '
    'anchor. NOT ERASABLE: it is inside the hash chain. NULL on every row '
    'written since migration 0013.';
COMMENT ON COLUMN handle_log.handle IS
    'PRE-CUTOVER ONLY. The whole handle, which for an email-tier handle spells '
    'the owner address out a second time. NULL since migration 0013.';
COMMENT ON COLUMN handle_log.owner_token IS
    'POST-CUTOVER. Opaque random id; the address lives only in log_owner_tokens. '
    'Delete that mapping row (registrar::forget_anchor) and this row becomes '
    'unlinkable to a person while the chain still verifies.';
COMMENT ON COLUMN handle_log.handle_name IS
    'POST-CUTOVER. The handle with its anchor removed. NULL for anchor-level '
    'actions that concern no handle. Reassembled as <handle_name>.<anchor> by '
    'the owner-scoped read, which already knows the anchor.';
COMMENT ON TABLE log_owner_tokens IS
    'The deletable half of the crypto-shredding scheme in migration 0013. One '
    'stable random token per anchor. Deleting a row erases the only link between '
    'that anchor and its post-cutover handle_log entries. Ordinary table: no '
    'chain, no append-only trigger, meant to be destroyed a row at a time.';

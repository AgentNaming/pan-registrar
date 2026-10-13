-- Normalize the anchor a re-homed handle stored (SPEC-NAMING §2, §5.6).
--
-- THE BUG. `registrar::rehome_in` filled `handles.email` by splitting the
-- DISPLAY handle out of the signed re-home statement instead of putting it
-- through `normalize_email`. The signer chooses the case of that string, so a
-- statement for `Agent.Ann@Example.com` wrote `Ann@Example.com` into a column
-- every other writer stores lowercased (`claim` takes it from a session, and
-- `mint_session_as` normalizes). `release()` and `mine()` compare `email = $1`
-- with no folding, so a row written that way was:
--
--   * missing from its owner's roster (`GET /api/handles/mine`),
--   * impossible for its owner to release (`POST /api/handles/release` -> 401),
--   * skipped by the account-closure cascade in `services/`, which enumerates an
--     account's names through `GET /api/partner/handles` (also `mine`) -- so
--     closing the account left the name standing,
--   * absent from its owner's own `/api/discover` listing, which lowercases the
--     anchor before calling `mine`.
--
-- The write path is fixed in the same change as this file. This repairs rows
-- already written by it.
--
-- WHY THIS CANNOT COLLIDE. `handles` has exactly one unique index:
-- `idx_handles_active` on `(handle_key) WHERE released_at IS NULL` (migration
-- 0002). `email` appears only in `idx_handles_email`, which is not unique.
-- Nothing below writes `handle_key`, so no unique index is touched, and two rows
-- folding onto the same address is just two rows with the same address -- which
-- the table already permits and every anchor holding two handles already has.
-- `operators.email` IS a primary key and so CAN collide; step 1 handles that
-- explicitly and says why.
--
-- WHY THIS CANNOT CHANGE WHICH HANDLE RESOLVES. Resolution keys on `handle_key`
-- (`resolve`, `resolve_rehomed`) or on the bound agent key (`resolve_by_agent`).
-- `email` appears in no resolution predicate at all. And `handle_key` is already
-- `lower(handle)`, so `Agent.ANN@x.com` and `Agent.ann@x.com` have always been
-- ONE handle here: lowering the stored anchor cannot move a handle to an anchor
-- other than the one its own name spells out in plain sight (§2). What changes is
-- visibility to the rightful owner, in the owner's favour, and only for rows
-- whose anchor is not already normalized.
--
-- Two consequences, stated rather than discovered:
--
--   * A repaired handle can now appear in its owner's `/api/discover` listing.
--     That listing is gated on `operators.discoverable`, which defaults false and
--     is only ever set by the owner under a verified session (§5.4), so this
--     exposes a handle only where its own owner already opted in.
--
--   * `handle_log` is NOT touched. It is append-only and hash-chained (§6), and
--     rewriting settled history is the one act the chain exists to make
--     detectable. Entries written after migration 0013 were never affected --
--     they key on `owner_token`, which `anchor_key()` already normalizes. Entries
--     written BEFORE 0013 by a migration in do carry a mixed-case address in
--     plaintext, and stay unreadable by their owner, because `log_entries`
--     matches pre-cutover rows with `email = $1`. That residue is disclosed here,
--     not repaired.

-- 1. The operator record FIRST, because resolution finds it through
--    `handles.email` (`api::resolve_handle`, `api::card_page`) and §5.1 marks it
--    required on every card. Normalizing `handles.email` while leaving
--    `operators.email` alone would make a re-homed handle's card lose the
--    operator name it serves today, so the two move together.
--
--    This is the one statement here that could collide, `operators.email` being
--    a primary key, and the ordering is what stops it: fold first, then rename.
--    A mixed-case operator row can only have come from `rehome_in`'s
--    `ON CONFLICT (email) DO NOTHING` insert, whose display name is either one
--    copied from the losing registrar's signed referral or the anchor's local
--    part standing in. The normalized row's name was chosen by the owner under a
--    verified session, so where both exist the owner's own label is the one to
--    keep. Folding also cannot silently enable discovery: `rehome_in` never
--    writes `discoverable`, so a mixed-case operator row always carries the
--    `false` default (migration 0009).
DELETE FROM operators o
 WHERE o.email <> lower(trim(o.email))
   AND EXISTS (SELECT 1 FROM operators n WHERE n.email = lower(trim(o.email)));

--    `updated_at` is deliberately left alone: it means "when the owner last
--    changed their display name", and this repair is not that.
UPDATE operators
   SET email = lower(trim(email))
 WHERE email <> lower(trim(email));

-- 2. The handles themselves. This is the row that release, the roster and the
--    closure cascade were all missing.
UPDATE handles
   SET email = lower(trim(email))
 WHERE email <> lower(trim(email));

-- 3. `anchor` is the anchor TIER -- 'email' or 'domain' (migration 0003) -- not
--    an address. `rehome_in` bound the split-out address into it as well, making
--    a re-homed row the only one in the table whose tier is an email address.
--    Neither valid value contains '@', which makes the repair exact: an '@' in
--    that column is this bug's handwriting and nothing else's. No code branches
--    on the column (it is served in the owner's roster JSON and read nowhere), so
--    this corrects what an owner is shown and changes no behavior.
UPDATE handles SET anchor = 'email' WHERE anchor LIKE '%@%';

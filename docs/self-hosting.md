# Running a registrar

A registrar is one program and one PostgreSQL database. It answers HTTP, so put it behind whatever
terminates TLS for you.

## 1. A signing key

Every card the registrar serves is signed. Make the key once and keep the seed as secret as a password:

```bash
docker run --rm ghcr.io/agentnaming/pan-registrar:0.2.0 keygen
```

It prints `PAN_CARD_SEED=SA…` and, on standard error, the public key. Resolvers pin the public key the
first time they see it, so losing the seed means rotating (below), and leaking it means anyone can sign
cards as you.

## 2. Start it

The Compose setup in `deploy/compose` runs the registrar, PostgreSQL and a mail catcher:

```bash
cd deploy/compose
cp .env.example .env     # set PAN_CARD_SEED, PAN_SELF_URL, and real mail
docker compose up -d
```

Check it:

```bash
curl http://localhost:8080/healthz            # {"ok":true,"version":"0.2.0"}
curl http://localhost:8080/api/registrar-key   # the public key cards are signed with
```

Then open http://localhost:8080/app, claim a name, and read the code from Mailpit at
http://localhost:8025. `node tools/smoke.mjs` does the same from a script and checks the card's signature.

Without Docker, run the binary with `DATABASE_URL` pointing at PostgreSQL 14 or newer. It applies its own
migrations at start.

## 3. Real mail

Set `PAN_SMTP_URL` and `PAN_MAIL_FROM` (or `RESEND_API_KEY`). The sending domain should have SPF and DKIM
set up, or verification codes land in spam, and then nobody can claim a name.

## 4. Behind a load balancer

Set `PAN_SELF_URL` to the public origin. List the load balancer's addresses or ranges in
`PAN_TRUSTED_PROXIES`, so the rate limits count each caller and not the balancer. If another site's pages
call the claiming routes, list their origins in `PAN_ALLOWED_ORIGINS`.

## 5. Peers

To let names move in from another registrar, list it in `PAN_PEERS`, spelled exactly as it spells its own
`PAN_SELF_URL`, and pin its signing key once you know it: `https://peer.example|AB3…`. Names can always
move out; the registrar they move to decides whether to accept them.

## 6. Keep the history log honest

The log is append-only by trigger, which stops the application from rewriting it. It does not stop the
database's owner. To close that, once, as a superuser, make a separate role own the table and take the
application's rights away:

```sql
ALTER TABLE handle_log OWNER TO <migration_role>;   -- the app's role must not own it
REVOKE DELETE, TRUNCATE ON handle_log FROM <app_role>;
```

The registrar writes each entry's hash back after inserting it, so it still needs `UPDATE`. The triggers
allow only that one write. Check with `\dp handle_log`.

The registrar also signs a commitment to the log's head every hour (`PAN_COMMITMENT_INTERVAL_SECS`), at
`/api/log-commitments`. Archive them somewhere the database cannot reach: a commitment is evidence that
history was not removed only if it survives the database.

## 7. Backups

Back up the database with `pg_dump`. The seed is not in the database; keep it with your other secrets.

## 8. Rotating the signing key

1. Make a new key with `keygen`.
2. Set `PAN_CARD_SEED` to the new seed, and add the old public key to `PAN_CARD_KEYS_RETIRED`.
3. Restart. The registrar signs with the new key and publishes both, so resolvers that pinned the old one
   keep verifying.
4. Remove the old key from `PAN_CARD_KEYS_RETIRED` once its cards have expired (`PAN_CARD_TTL_SECS`).

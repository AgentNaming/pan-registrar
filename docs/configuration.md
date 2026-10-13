# Configuration

Every setting is an environment variable. The registrar says at startup what the important ones are set
to, and warns about each one that is missing in a way that matters.

## The three that decide what a registrar can do

| Variable | What it does | If unset |
|---|---|---|
| `PAN_CARD_SEED` | The key that signs every card and referral (an nkeys account seed, `SA…`). Make one with `pan-registrar keygen`. | **Resolution answers 503.** Every card must be signed (SPEC-NAMING §7.6), and an unsigned card is invalid (§5.3), so the registrar refuses rather than serve one. |
| `PAN_SELF_URL` | This registrar's public origin, such as `https://names.example.com`. | Names cannot move in, the referrals it serves cannot say who issued them, and it issues no log commitments. |
| `PAN_PEERS` | The registrars it accepts a name moving in from, separated by commas, each optionally pinned to its signing key: `https://peer.example\|AB3…`. | Names cannot move in. §5.6 requires the losing registrar to agree a name was released, and an unknown caller naming its own corroborating source is not that agreement. |

## The deployment

| Variable | Default | What it does |
|---|---|---|
| `DATABASE_URL` | none: an embedded PostgreSQL | The PostgreSQL database. Migrations run at start. |
| `PORT` | `8080` | The HTTP port. |
| `BIND_ADDR` | `0.0.0.0` | The interface to listen on. Use `127.0.0.1` for a test rig on a laptop. |
| `PAN_REGISTRAR_NAME` | `Personal Agent Naming` | How the registrar names itself in its mail and pages. |
| `PAN_HOME_URL` | none | Where people claim and manage names, when that is your own console. `/app` then redirects there. Unset, `/app` serves the built-in claim page. |
| `PAN_ALLOWED_ORIGINS` | none | Browser origins whose pages may call the claiming and binding routes, separated by commas or spaces. `*` allows any. The registrar's own pages need nothing here. |
| `PAN_TRUSTED_PROXIES` | none | Proxies whose `X-Forwarded-For` the registrar believes: addresses or ranges, separated by commas or spaces. Unset, the caller is the connection's own address and the header is ignored. Behind a load balancer, list its ranges, or every caller shares its address and its rate limits. |
| `LB_PUBLIC_IPS` | none | Older name for load balancer addresses; added to `PAN_TRUSTED_PROXIES`. |
| `PAN_SPEC_PATH` | `SPEC-NAMING.md` | The specification file served at `/spec`. |
| `PAN_DEFAULT_MESH` | none | The mesh written on a card's `agentmesh` endpoint when the agent's record names none. |
| `RUST_LOG` | `info` | Log level. |

## Mail

The registrar sends verification codes, the notice that a name moved, and, if turned on, invitations.

| Variable | What it does |
|---|---|
| `PAN_SMTP_URL` | An SMTP server as a URL: `smtps://user:password@smtp.example.com`, or `smtp://host:587?tls=required` for STARTTLS. Takes precedence over Resend. |
| `RESEND_API_KEY` | The Resend API, used when `PAN_SMTP_URL` is unset. |
| `PAN_MAIL_FROM` | The sender address. `RESEND_FROM` is the older name. |

With neither provider set, the registrar is in development mode: a verification code is written to the
log instead of sent.

## Partners and moderation (SPEC-NAMING §3.1, §9)

| Variable | What it does | If unset |
|---|---|---|
| `PAN_DELEGATE_SECRET` | The **witnessing** credential: a partner platform that has verified a member's email gets a session for that one address, and can claim, bind and release only under it. | The partner routes answer 501. |
| `PAN_DELEGATE_PARTNER` | The partner's name, recorded on what it claims as `delegated:<name>`. | `partner` |
| `PAN_OPERATOR_SECRET` | The **moderation** credential: take down any name, read any owner's names. Keep it different from the witnessing secret. | Moderation falls back to the witnessing secret, and the log says so at every start. |

## Cards and the log

| Variable | Default | What it does |
|---|---|---|
| `PAN_CARD_KEYS_RETIRED` | none | Public keys still published after a rotation, so resolvers that pinned one keep verifying. |
| `PAN_CARD_TTL_SECS` | `3600` | How long a signed card is valid. Caches are told a tenth of it. |
| `PAN_COMMITMENT_INTERVAL_SECS` | `3600` | How often a signed commitment to the log's head is issued when nothing else is happening. |

## Rate limits

| Variable | Default | Counts |
|---|---|---|
| `PAN_CODES_MAX_PER_IP_HOUR` | 15 | Verification codes requested from one address in an hour |
| `PAN_CODES_MAX_PER_HOUR` | 500 | Verification codes across the registrar in an hour |
| `PAN_PAIR_MAX_PER_IP_HOUR` | 60 | Pairing attempts from one address in an hour |
| `PAN_REHOME_MAX_PER_HOUR` | 60 | Re-home statements in an hour |
| `PAN_REVERSE_MAX_PER_HOUR` | 300 | Reverse lookups (key to name) from one address in an hour |
| `PAN_REVERSE_TRUSTED_IPS` | none | Addresses allowed the higher reverse-lookup ceiling below, such as a platform that checks names on every registration |
| `PAN_REVERSE_TRUSTED_MAX_PER_HOUR` | 20000 | The ceiling for those addresses |
| `PAN_REVERSE_REQUIRE_DISCOVERABLE` | off | Answer reverse lookups only for owners who opted in to discovery (§5.4) |
| `PAN_INVITES_MAX_PER_DAY` | 25 | Invitations one owner may send in a day |
| `PAN_INVITES_MAX_PER_IP_DAY` | 50 | Invitations from one address in a day |

## Optional features

| Variable | What it does |
|---|---|
| `PAN_INVITE_ENABLED` | `1` turns on `POST /api/invite`: a signed-in owner asks the registrar to email someone an invitation. Not part of SPEC-NAMING; off by default. |

## Tests only

| Variable | What it does |
|---|---|
| `PAN_DB_TESTS` | `1` runs the database tests. |
| `PAN_TEST_DATABASE_URL` | A PostgreSQL server for the database tests; each test gets a fresh database on it. Unset, each test starts an embedded PostgreSQL. |
| `CATALOG_DATA_DIR`, `CATALOG_PG_RUNTIME_DIR` | Where the embedded PostgreSQL keeps its data and its binaries. |

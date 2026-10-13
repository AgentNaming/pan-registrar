# Personal Agent Naming registrar

A registrar for [Personal Agent Naming](https://agentnaming.ai): it gives an agent a public name on its
owner's email address, such as `Helper.ann@example.com`, binds the name to the agent's own key, and
answers lookups with a card it signs. The protocol is SPEC-NAMING ([the specification](SPEC-NAMING.md);
its home is [AgentNaming/personal-agent-naming](https://github.com/AgentNaming/personal-agent-naming)).

Anyone can run one. Names can move between registrars without changing the agent behind them, and the
owner of an email domain outranks every registrar for the names on that domain.

Sponsored by [AgentMesh](https://agentmesh.ai), which runs a registrar at `naming.agentmesh.ai`.

## What it does

- **Claiming.** A person proves an email address with a six-digit code and claims names on it. Each
  owner has a public display name shown on their names' cards (SPEC-NAMING §3).
- **Binding.** A name is bound to an agent's Ed25519 key by pairing: the registrar issues a one-time code,
  and the agent signs `pan-pair-v1:<code>:<agent id>` with its own key (§4). The key behind a name can
  change, and every change is recorded and shown (§4.4).
- **Resolution.** `GET /api/resolve?handle=…` returns the name's card, signed with the registrar's key, and
  WebFinger answers for the same name as an `acct:` URI (§5). The signing keys are published at
  `/api/registrar-key`.
- **Moving between registrars.** A name can re-home to another registrar with a statement signed by the
  agent's key. The old registrar answers with a signed referral and can never issue the name again (§5.6).
- **History.** Every claim, binding and release is written to an append-only, hash-chained log, readable
  only by the owner of the email it concerns, with signed commitments to its head (§6).
- **Partners.** A platform that has already verified its members' email can claim and bind on their
  behalf with a witnessing credential (§3.1), separate from the operator's moderation credential (§9).

A claim and pair page is served at `/app`, so a registrar works on its own with no other software.

## Run it

With Docker:

```bash
cd deploy/compose
cp .env.example .env
docker run --rm ghcr.io/agentnaming/pan-registrar:0.2.0 keygen   # put the PAN_CARD_SEED line in .env
docker compose up -d
```

The registrar answers at http://localhost:8080 and its claim page is http://localhost:8080/app. Mail goes
to a Mailpit container at http://localhost:8025 until you set `PAN_SMTP_URL`.

From source, with a current stable Rust:

```bash
cargo run
```

With no `DATABASE_URL`, it starts its own embedded PostgreSQL, so this works with nothing else installed.
Without `PAN_CARD_SEED` it starts but refuses to resolve names, because every card must be signed.

[docs/self-hosting.md](docs/self-hosting.md) covers a real deployment, and
[docs/configuration.md](docs/configuration.md) lists every setting.

## Test it

```bash
cargo test                                               # the fast tests
PAN_DB_TESTS=1 cargo test -- --ignored --test-threads=1  # the database tests (embedded PostgreSQL,
                                                         # or set PAN_TEST_DATABASE_URL)
```

`conformance/` holds the wire vectors the tests read and the registrar conformance tests, which run
against two registrars that name each other as peers. `tools/smoke.mjs` claims, pairs and resolves a name
against a running registrar.

## Repository

| Path | What it is |
|---|---|
| `src/` | The registrar: `api.rs` (HTTP), `registrar.rs` (claiming, binding, resolution, re-homing, the log), `config.rs` (settings), `mail.rs` (outbound mail) |
| `migrations/` | The schema, applied at start. Applied migrations are never edited. |
| `web/app.html` | The claim and pair page |
| `deploy/` | The Dockerfile and the Compose setups |
| `conformance/` | Wire vectors and conformance tests, exported from the specification's sources |
| `SPEC-NAMING.md` | A copy of the specification, exported with it |

## License

Apache-2.0. See [LICENSE](LICENSE).

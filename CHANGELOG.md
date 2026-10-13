# Changelog

## 0.2.0

The first release from this repository. Before it, the registrar was AgentMesh's naming service, built
inside AgentMesh's repository.

- Runs on its own: no AgentMesh host names compiled in, and its name, console address, allowed origins
  and trusted proxies are settings (`PAN_REGISTRAR_NAME`, `PAN_HOME_URL`, `PAN_ALLOWED_ORIGINS`,
  `PAN_TRUSTED_PROXIES`).
- A claim and pair page at `/app`.
- Mail over SMTP (`PAN_SMTP_URL`) as well as Resend, and development mode writes codes to the log.
- `X-Forwarded-For` is believed only from proxies listed in `PAN_TRUSTED_PROXIES`. Before, it was always
  read, so a registrar with no proxy in front could be told any caller address and its per-address limits
  stepped around.
- Canonical JSON follows RFC 8785 exactly: keys sort by UTF-16 code units and numbers take their
  ECMAScript form. Every card and log entry written before is byte-identical under it.
- Codes come straight from the operating system's random source, with no modulo bias.
- `pan-registrar keygen` makes a card signing key.
- `POST /api/invite` is off unless `PAN_INVITE_ENABLED` is set.
- The database tests can run against any PostgreSQL (`PAN_TEST_DATABASE_URL`).

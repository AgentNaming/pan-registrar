-- Spent re-home statements (SPEC-NAMING §5.6 hardening).
--
-- A pan-rehome-v1 statement is a bearer authorization: it names a handle, a
-- destination and a timestamp, and anyone holding the bytes can present them.
-- Without a record of what has already been spent, a statement captured once
-- replays forever — including after the owner has moved the name somewhere
-- else. Each registrar keeps its own ledger; a statement is recorded only
-- after it has been acted on successfully, so a failed attempt can be retried
-- but a successful one cannot be replayed.
CREATE TABLE IF NOT EXISTS rehome_statements (
    statement_hash TEXT PRIMARY KEY,
    handle         TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    action         TEXT NOT NULL,
    used_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Statements expire from usefulness on their own (the freshness window), so
-- this table only needs to retain a window's worth; the index is for pruning.
CREATE INDEX IF NOT EXISTS rehome_statements_used_at ON rehome_statements (used_at);

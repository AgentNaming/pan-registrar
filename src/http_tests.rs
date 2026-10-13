//! The HTTP surface, driven over a real socket.
//!
//! WHY THIS EXISTS. Nothing in this crate used to exercise a route. The status
//! codes on the delegated-release path — 401 with no token, 403 for a session
//! that is not delegated, 403 for another anchor's handle, 400 for a name nobody
//! holds — were readable in the handler and asserted nowhere, so a refactor that
//! turned one of them into a 500, or into a 200, would have passed every test in
//! the crate. The same was true of which shared secret opens which route, which
//! is the whole of the §3.1/§9 credential separation.
//!
//! WHY A REAL SOCKET and not axum's tower plumbing. Driving a `Router` through
//! `tower::ServiceExt::oneshot` would need `tower` as a dependency this crate
//! does not have, and it skips `into_make_service_with_connect_info`, which
//! `main` uses and which the code-issuing routes read the client address from. A
//! loopback listener plus `reqwest` — already a dependency, for outbound mail and
//! peer corroboration — exercises the same stack `main` serves. It binds
//! 127.0.0.1 only, so running the suite never opens a service to the network or
//! asks for a firewall exception (the reason `BIND_ADDR` exists).
//!
//! WHAT NEEDS A DATABASE AND WHAT DOES NOT. The credential gate runs before any
//! storage access, so those cases hold a pool that never connects and run in
//! plain `cargo test`. Everything that reaches a handle needs real rows, so it
//! follows the existing convention: `#[ignore]`, gated on `PAN_DB_TESTS=1`, one
//! embedded PostgreSQL each.
//!
//!     PAN_DB_TESTS=1 cargo test http -- --ignored --test-threads=1

use std::net::SocketAddr;

use serde_json::json;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::registrar;

/// A running registrar: the real router on a loopback port, over whatever
/// database the case needs.
struct Registrar {
    base: String,
    pool: PgPool,
    client: reqwest::Client,
    server: tokio::task::JoinHandle<()>,
    /// Held so the embedded server outlives the test — dropping it stops it.
    /// None for the cases that never reach storage.
    _pg: Option<postgresql_embedded::PostgreSQL>,
}

impl Drop for Registrar {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Registrar {
    async fn serving(pool: PgPool, pg: Option<postgresql_embedded::PostgreSQL>) -> Self {
        let app = crate::api::router(pool.clone());
        let listener =
            tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("bind a loopback port");
        let addr = listener.local_addr().expect("local_addr");
        let server = tokio::spawn(async move {
            let _ = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await;
        });
        Registrar {
            base: format!("http://{addr}"),
            pool,
            client: reqwest::Client::new(),
            server,
            _pg: pg,
        }
    }

    /// A registrar with a migrated database behind it, and a signing key, since
    /// resolution refuses outright without one (§7.6).
    async fn with_storage() -> Self {
        ensure_card_key();
        let (pg, pool) = registrar::test_db::fresh_db().await;
        Self::serving(pool, pg).await
    }

    /// A registrar whose pool is never dialled. Legitimate only for cases that
    /// are refused before the handler touches storage — which is exactly what
    /// makes those cases worth having: a credential check that reached the
    /// database would be a credential check that leaked whether a row exists.
    async fn without_storage() -> Self {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
            .expect("a lazy pool needs no server");
        Self::serving(pool, None).await
    }

    async fn post(
        &self,
        path: &str,
        headers: &[(&str, &str)],
        body: serde_json::Value,
    ) -> (u16, serde_json::Value) {
        let mut req = self.client.post(format!("{}{path}", self.base)).json(&body);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        Self::finish(req).await
    }

    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> (u16, serde_json::Value) {
        let mut req = self.client.get(format!("{}{path}", self.base));
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        Self::finish(req).await
    }

    /// Status and parsed body together, because both matter: a 403 that says the
    /// wrong thing is a different bug from a 403.
    async fn finish(req: reqwest::RequestBuilder) -> (u16, serde_json::Value) {
        let resp = req.send().await.expect("the registrar answered");
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let body = serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
        (status, body)
    }

    /// A delegated session, minted the way a partner mints one: over HTTP, with
    /// the witnessing secret.
    async fn delegated_session(&self, secret: &str, email: &str) -> String {
        let (status, body) = self
            .post(
                "/api/handles/session-delegated",
                &[("x-delegate-secret", secret)],
                json!({ "email": email }),
            )
            .await;
        assert_eq!(status, 200, "minting a delegated session: {body}");
        body["token"].as_str().expect("a token").to_string()
    }

    /// A directly verified session. Minted in-process rather than over HTTP
    /// because the HTTP path requires reading a code out of an email; the row is
    /// the same one `POST /api/handles/verify` writes.
    async fn email_session(&self, email: &str) -> String {
        registrar::mint_session_as(&self.pool, email, "email")
            .await
            .expect("an email-provenance session")
            .to_string()
    }

    async fn claim(&self, token: &str, name: &str) -> String {
        let bearer = format!("Bearer {token}");
        let (status, body) = self
            .post(
                "/api/handles/claim",
                &[("authorization", &bearer)],
                json!({ "name": name, "operator_name": "Test Operator" }),
            )
            .await;
        assert_eq!(status, 200, "claiming {name}: {body}");
        body["handle"].as_str().expect("a handle").to_string()
    }
}

fn unique_email(who: &str) -> String {
    format!("{who}-{}@example.com", uuid::Uuid::new_v4().simple())
}

/// A throwaway card signing key, so resolution answers 200/404 instead of the
/// 503 a registrar with no key is required to serve (§5.3, §7.6).
///
/// `CARD_KEY` is a process-wide `OnceLock`, so this must never run with the seed
/// unset — that would latch "no key" for every later test in the binary. It sets
/// the seed first and generates a real one, and the second call onward is a
/// harmless no-op because the lock is already filled.
fn ensure_card_key() {
    let (_public, seed) = crate::test_identity().expect("a fresh signing key");
    std::env::set_var("PAN_CARD_SEED", seed);
    let _ = crate::api::init_card_key();
}

fn clear_secrets() {
    std::env::remove_var("PAN_DELEGATE_SECRET");
    std::env::remove_var("PAN_OPERATOR_SECRET");
}

/// The gate the database-backed cases open with, matching the registrar's own.
fn db_enabled(name: &str) -> bool {
    if std::env::var("PAN_DB_TESTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped {name}: set PAN_DB_TESTS=1");
    false
}

/// SPEC-NAMING §9, over the wire: once a deployment splits its secrets, the
/// credential a partner integration holds does not open a moderation route.
///
/// Runs without a database on purpose. Every case here must be refused before the
/// handler reaches storage, and asserting that from the outside is how we know it
/// is: a credential check that touched the database could leak whether a row
/// exists to a caller holding no valid secret at all.
///
/// It is also the only test in this crate that mutates the process environment
/// while the rest of the suite may be running in parallel. That is safe only
/// because nothing else reads these two variables — the pure credential tests in
/// `api::credentials` take their inputs as arguments precisely so they do not, and
/// every other environment reader is behind `PAN_DB_TESTS`, which runs
/// `--test-threads=1`. Keep it that way, or move this behind the gate too.
#[tokio::test]
async fn the_moderation_routes_refuse_the_witnessing_secret_once_the_secrets_are_split() {
    let reg = Registrar::without_storage().await;
    let roster = "/api/partner/handles?email=someone@example.com";
    let takedown = json!({ "handle": "Agent.someone@example.com" });
    let mint = json!({ "email": "someone@example.com" });

    // NEITHER SECRET SET: both authorities are off, and the answer is 501, not
    // 401 — an operator has to be able to tell "not enabled here" from "wrong
    // secret", and a 401 to a caller holding the right secret would send them
    // hunting for a typo that does not exist.
    clear_secrets();
    let (status, body) = reg.post("/api/partner/release", &[("x-delegate-secret", "anything")], takedown.clone()).await;
    assert_eq!(status, 501, "moderation with nothing configured: {body}");
    assert_eq!(body["error"], json!("moderation not configured"));
    assert_eq!(reg.get(roster, &[("x-delegate-secret", "anything")]).await.0, 501);
    let (status, body) = reg.post("/api/handles/session-delegated", &[("x-delegate-secret", "anything")], mint.clone()).await;
    assert_eq!(status, 501, "witnessing with nothing configured: {body}");
    assert_eq!(body["error"], json!("delegation not configured"));

    // ONLY THE OLD SECRET SET — the deployed configuration this change had to not
    // break. Moderation falls back to it, so the credential is accepted and the
    // request proceeds far enough to need the database. That leg is asserted in
    // `the_moderation_fallback_works_until_a_deployment_splits_the_secrets`,
    // which has one. What can be asserted here is that a WRONG secret is still
    // refused, and refused as a moderation failure.
    std::env::set_var("PAN_DELEGATE_SECRET", "witness-only");
    let (status, body) = reg.post("/api/partner/release", &[("x-delegate-secret", "not-it")], takedown.clone()).await;
    assert_eq!(status, 401, "a wrong secret under the fallback: {body}");
    assert_eq!(body["error"], json!("invalid operator secret"));

    // SPLIT — what §9 asks for. THE PROPERTY: the witnessing secret, which lives
    // in a partner platform's configuration and is used on every signup, no
    // longer opens either moderation route. Whichever header it arrives in.
    std::env::set_var("PAN_OPERATOR_SECRET", "moderate-only");
    for header in ["x-delegate-secret", "x-operator-secret"] {
        let (status, body) = reg.post("/api/partner/release", &[(header, "witness-only")], takedown.clone()).await;
        assert_eq!(status, 401, "witnessing secret in {header} must not release: {body}");
        assert_eq!(body["error"], json!("invalid operator secret"));
        let (status, body) = reg.get(roster, &[(header, "witness-only")]).await;
        assert_eq!(status, 401, "witnessing secret in {header} must not read a roster: {body}");
    }

    // And the converse, which is the half that makes the two authorities able to
    // fail separately: the moderation secret does not mint delegated sessions, so
    // a leaked moderation credential cannot start claiming names under other
    // people's anchors.
    let (status, body) = reg.post("/api/handles/session-delegated", &[("x-delegate-secret", "moderate-only")], mint).await;
    assert_eq!(status, 401, "the moderation secret must not witness: {body}");
    assert_eq!(body["error"], json!("invalid delegate secret"));

    // A missing header is the same refusal as a wrong one.
    assert_eq!(reg.post("/api/partner/release", &[], takedown).await.0, 401);
    clear_secrets();
}

/// The other side of the split, with a database: the fallback really does
/// authorize, so setting only the old secret keeps moderation working — and
/// setting the new one really does take that authority away from the old secret.
#[tokio::test]
#[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
async fn the_moderation_fallback_works_until_a_deployment_splits_the_secrets() {
    if !db_enabled("the_moderation_fallback_works_until_a_deployment_splits_the_secrets") {
        return;
    }
    clear_secrets();
    std::env::set_var("PAN_DELEGATE_SECRET", "witness-only");
    let reg = Registrar::with_storage().await;

    let email = unique_email("ann");
    let token = reg.delegated_session("witness-only", &email).await;
    let handle = reg.claim(&token, "public-agent").await;
    let roster = format!("/api/partner/handles?email={email}");

    // BACKWARD COMPATIBILITY, asserted rather than assumed: with PAN_OPERATOR_SECRET
    // unset, the moderation route answers the old secret exactly as it did before
    // the split existed. This is what would have broken the deployed
    // account-closure cascade had the new secret been made mandatory.
    let (status, body) = reg.get(&roster, &[("x-delegate-secret", "witness-only")]).await;
    assert_eq!(status, 200, "the fallback must keep moderation working: {body}");
    assert_eq!(body["handles"][0]["handle"], json!(handle));

    // Now split them. The same request, unchanged, must stop working.
    std::env::set_var("PAN_OPERATOR_SECRET", "moderate-only");
    let (status, _) = reg.get(&roster, &[("x-delegate-secret", "witness-only")]).await;
    assert_eq!(status, 401, "after the split the witnessing secret is not a moderation key");

    // The moderation secret works in either header, which is what lets an
    // operator split the secrets here before the separately deployed caller
    // changes a header.
    for header in ["x-delegate-secret", "x-operator-secret"] {
        let (status, body) = reg.get(&roster, &[(header, "moderate-only")]).await;
        assert_eq!(status, 200, "the moderation secret in {header}: {body}");
        assert_eq!(body["handles"][0]["handle"], json!(handle));
    }
    clear_secrets();
}

/// `POST /api/handles/release-delegated`, refused four ways. Each status is a
/// different answer to a different question, and a caller needs them apart: 401
/// says the session is not usable, 403 says the session is real but is the wrong
/// kind or speaks for the wrong anchor, and 400 says the session is right and the
/// name is not there.
#[tokio::test]
#[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
async fn release_delegated_refuses_with_the_status_that_names_the_reason() {
    if !db_enabled("release_delegated_refuses_with_the_status_that_names_the_reason") {
        return;
    }
    clear_secrets();
    std::env::set_var("PAN_DELEGATE_SECRET", "witness-only");
    let reg = Registrar::with_storage().await;

    let ann = unique_email("ann");
    let bob = unique_email("bob");
    let ann_delegated = reg.delegated_session("witness-only", &ann).await;
    let ann_handle = reg.claim(&ann_delegated, "public-agent").await;
    let bob_delegated = reg.delegated_session("witness-only", &bob).await;
    let bob_handle = reg.claim(&bob_delegated, "public-agent").await;

    // 1. NO TOKEN. 401.
    let (status, body) =
        reg.post("/api/handles/release-delegated", &[], json!({ "handle": ann_handle })).await;
    assert_eq!(status, 401, "a request with no session: {body}");
    assert_eq!(body["ok"], json!(false));

    // A malformed or expired token is the same 401 — the route must not leak
    // whether a token that failed to parse belonged to anyone.
    let (status, _) = reg
        .post(
            "/api/handles/release-delegated",
            &[("authorization", "Bearer not-a-uuid")],
            json!({ "handle": ann_handle }),
        )
        .await;
    assert_eq!(status, 401, "a token that is not even a token");
    let (status, _) = reg
        .post(
            "/api/handles/release-delegated",
            &[("authorization", &format!("Bearer {}", uuid::Uuid::new_v4()))],
            json!({ "handle": ann_handle }),
        )
        .await;
    assert_eq!(status, 401, "a well-formed token nobody minted");

    // 2. A DIRECTLY VERIFIED SESSION. 403, and it is not a permission problem —
    // the owner has MORE authority here, not less. §3.1's disclosure rule needs
    // a `released` entry's `via` to be a fact rather than a guess, so an owner
    // proving their own mailbox is sent to the plain route.
    let ann_direct = reg.email_session(&ann).await;
    let bearer = format!("Bearer {ann_direct}");
    let (status, body) = reg
        .post(
            "/api/handles/release-delegated",
            &[("authorization", &bearer)],
            json!({ "handle": ann_handle }),
        )
        .await;
    assert_eq!(status, 403, "a directly verified session on the delegated route: {body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("requires a delegated session"),
        "the refusal must say which route to use: {body}"
    );

    // 3. ANOTHER ANCHOR'S HANDLE. 403. The security property of the whole route:
    // a delegated session speaks for one anchor and may give up what that anchor
    // holds, nothing else.
    let bearer = format!("Bearer {ann_delegated}");
    let (status, body) = reg
        .post(
            "/api/handles/release-delegated",
            &[("authorization", &bearer)],
            json!({ "handle": bob_handle }),
        )
        .await;
    assert_eq!(status, 403, "ann's session releasing bob's handle: {body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("not anchored to the email"),
        "the refusal must name the reason: {body}"
    );

    // 4. THE SESSION'S OWN ANCHOR, BUT NO SUCH HANDLE. 400, not 403 and not 404:
    // the caller is entitled to act here and the request is simply about a name
    // nobody holds, which a caller needs to tell apart from its own no-op.
    let (status, body) = reg
        .post(
            "/api/handles/release-delegated",
            &[("authorization", &bearer)],
            json!({ "handle": format!("Nope.{ann}") }),
        )
        .await;
    assert_eq!(status, 400, "a name nobody holds: {body}");
    assert!(
        body["error"].as_str().unwrap_or_default().contains("no active handle"),
        "the refusal must distinguish a missing name from a forbidden one: {body}"
    );

    // REFUSED MEANS UNTOUCHED. Four refusals and both handles still resolve.
    for h in [&ann_handle, &bob_handle] {
        let (status, body) = reg.get(&format!("/api/resolve?handle={h}"), &[]).await;
        assert_eq!(status, 200, "{h} must still resolve after the refusals: {body}");
    }
    clear_secrets();
}

/// §4.4 over the wire: after a rebind, the resolution surface and the public
/// card page both say so. The reader this exists for is the counterparty who
/// resolves the name for the first time AFTER the key changed, whom §5.3
/// pinning cannot warn.
#[tokio::test]
#[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
async fn a_rebind_is_visible_on_the_card_and_on_the_card_page() {
    if !db_enabled("a_rebind_is_visible_on_the_card_and_on_the_card_page") {
        return;
    }
    clear_secrets();
    let reg = Registrar::with_storage().await;

    let email = unique_email("ann");
    let handle = registrar::claim(&reg.pool, &email, "PublicAgent", None, "email")
        .await
        .expect("claim");

    // The §4.1 ceremony, twice: first with k1, then re-pointing the name to k2.
    let pair = |public: String, seed: String| {
        let pool = reg.pool.clone();
        let email = email.clone();
        let handle = handle.clone();
        async move {
            use base64::Engine;
            let (code, _) = registrar::pair_start(&pool, &email, &handle).await.expect("pair start");
            let kp = nkeys::KeyPair::from_seed(&seed).expect("keypair");
            let sig = kp.sign(format!("pan-pair-v1:{code}:{public}").as_bytes()).expect("sign");
            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
            registrar::pair_complete(&pool, &code, &public, &sig_b64).await.expect("pair complete");
        }
    };
    let (k1, seed1) = crate::test_identity().expect("k1");
    pair(k1.clone(), seed1).await;
    let (k2, seed2) = crate::test_identity().expect("k2");
    pair(k2.clone(), seed2).await;

    // The card: `key_history` is inside the signed document, so a first-sight
    // resolver gets the change with the same authenticity as the card itself.
    let (status, body) = reg.get(&format!("/api/resolve?handle={handle}"), &[]).await;
    assert_eq!(status, 200, "the rebound handle resolves: {body}");
    let history = body["card"]["key_history"].as_array().expect("key_history on the card");
    assert_eq!(history.len(), 1, "one recorded change: {body}");
    assert_eq!(history[0]["old_key"], json!(k1));
    assert_eq!(history[0]["new_key"], json!(k2));
    assert_eq!(history[0]["method"], json!("agent-key"));
    assert!(history[0]["changed_at"].as_str().is_some(), "the change is dated");
    assert!(body["registrar_sig"].as_str().is_some(), "the card carrying it is signed");
    // And the card's address is the NEW key, which is exactly the pairing of
    // facts a reader needs: current key plus when it became current.
    assert_eq!(body["card"]["endpoints"][0]["agent_id"], json!(k2));

    // The human-readable page states it in plain words.
    let (status, page) = reg.get(&format!("/a/{handle}"), &[]).await;
    assert_eq!(status, 200);
    let html = page["raw"].as_str().expect("the card page is HTML");
    assert!(
        html.contains("This name moved to a new key on"),
        "the page must state the move plainly: {html}"
    );
    assert!(
        html.contains("History before that date belongs to the previous key"),
        "the page must say what the history before the move belongs to: {html}"
    );
}

/// A partner's claims keep to the partner name rule (slug.rs); a person signed
/// in directly keeps the whole §2 grammar, dots and capitals included.
#[tokio::test]
#[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
async fn a_delegated_claim_keeps_to_the_partner_name_rule() {
    if !db_enabled("a_delegated_claim_keeps_to_the_partner_name_rule") {
        return;
    }
    clear_secrets();
    std::env::set_var("PAN_DELEGATE_SECRET", "witness-only");
    let reg = Registrar::with_storage().await;

    let email = unique_email("dee");
    let token = reg.delegated_session("witness-only", &email).await;
    let bearer = format!("Bearer {token}");
    for bad in ["Genesis", "my.agent", "-edge", "has space"] {
        let (status, body) = reg
            .post("/api/handles/claim", &[("authorization", &bearer)], json!({ "name": bad, "operator_name": "Test Operator" }))
            .await;
        assert_eq!(status, 400, "a delegated claim of {bad:?} must be refused: {body}");
    }
    assert_eq!(reg.claim(&token, "genesis").await, format!("genesis.{email}"));

    let direct = reg.email_session(&unique_email("eve")).await;
    assert!(reg.claim(&direct, "My.Agent").await.starts_with("My.Agent."));
}

/// The success path: a partner closing a member's account gives up that member's
/// name, and the record says the owner did it.
#[tokio::test]
#[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
async fn release_delegated_gives_up_the_sessions_own_handle() {
    if !db_enabled("release_delegated_gives_up_the_sessions_own_handle") {
        return;
    }
    clear_secrets();
    std::env::set_var("PAN_DELEGATE_SECRET", "witness-only");
    let reg = Registrar::with_storage().await;

    let email = unique_email("cara");
    let token = reg.delegated_session("witness-only", &email).await;
    let handle = reg.claim(&token, "desk").await;
    let bearer = format!("Bearer {token}");

    let (status, body) = reg
        .post(
            "/api/handles/release-delegated",
            &[("authorization", &bearer)],
            json!({ "handle": handle }),
        )
        .await;
    assert_eq!(status, 200, "releasing the session anchor's own handle: {body}");
    assert_eq!(body["handle"], json!(handle));
    // §3 cooling-off, reported rather than implied: a caller has to be able to
    // tell the member when the name could be taken again, and by whom.
    let released_at = body["released_at"].as_str().expect("released_at");
    let claimable = body["claimable_after"].as_str().expect("claimable_after");
    assert!(claimable > released_at, "the window must end after it starts: {body}");

    // The tombstone: gone from resolution.
    let (status, _) = reg.get(&format!("/api/resolve?handle={handle}"), &[]).await;
    assert_eq!(status, 404, "a released handle must not resolve");

    // THE ATTRIBUTION (§3.1, §9). One `released` entry against the owner, with
    // the delegated provenance disclosed inside it — and no
    // `released_by_operator`, which would say the operator took a name its owner
    // gave up. Read through the owner's own session, which is the only route to
    // the log.
    let owner = reg.email_session(&email).await;
    let bearer = format!("Bearer {owner}");
    let (status, body) = reg.get("/api/handles/log", &[("authorization", &bearer)]).await;
    assert_eq!(status, 200, "the owner-scoped log read: {body}");
    let entries = body["entries"].as_array().expect("entries").clone();
    let releases: Vec<&serde_json::Value> =
        entries.iter().filter(|e| e["action"] == json!("released")).collect();
    assert_eq!(releases.len(), 1, "exactly one release entry: {body}");
    assert_eq!(releases[0]["handle"], json!(handle));
    assert_eq!(releases[0]["detail"]["via"], json!("delegated:partner"));
    assert!(
        !entries.iter().any(|e| e["action"] == json!("released_by_operator")),
        "a user-initiated release must not be recorded as operator moderation: {body}"
    );
    clear_secrets();
}

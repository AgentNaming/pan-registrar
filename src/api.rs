//! HTTP surface, v0: health, search, read, manual submission.
//! The ARD-compliant read interface will be a sibling router that projects
//! the same listings into the standard's shapes.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::model::SubmitListing;
use crate::registrar::{self, RegistrarError};
use crate::store;

pub fn router(pool: PgPool) -> Router {
    // Public reads stay readable from anywhere: resolution, WebFinger, the
    // signing key and consented discovery are the parts of this service other
    // people's pages are supposed to call.
    let public = Router::new()
        .route("/", get(ui_index))
        .route("/favicon.svg", get(favicon))
        // The registrar's own claim and pair page, or a redirect to the
        // operator's console when PAN_HOME_URL names one.
        .route("/app", get(app_page))
        .route("/app/", get(app_page))
        .route("/spec", get(spec_page))
        .route("/spec.md", get(spec_raw))
        .route("/healthz", get(healthz))
        .route("/api/listings/:id", get(get_one))
        .route("/api/resolve", get(resolve_handle))
        .route("/api/discover", get(discover))
        .route("/a/:handle", get(card_page))
        .route("/api/registrar-key", get(registrar_key))
        .route("/.well-known/webfinger", get(webfinger))
        .route("/api/log-commitments", get(log_commitments))
        .layer(tower_http::cors::CorsLayer::permissive());

    // Everything that changes state, and everything that needs a credential,
    // answers cross-origin only for origins this deployment names. It is not a
    // CSRF defence (auth here is a bearer, never an ambient cookie): it stops
    // an arbitrary page from driving the unauthenticated endpoints —
    // handles/start, pair/complete, rehome-in — through its visitors'
    // browsers, which is also how a per-IP limiter gets spread across a
    // residential address space. Non-browser callers send no Origin and are
    // unaffected. PAN_ALLOWED_ORIGINS overrides; "*" restores the old behavior.
    let guarded = Router::new()
        .route("/api/listings", post(submit))
        .route("/api/invite", post(invite))
        .route("/api/operator", get(operator_get).post(operator_set))
        .route("/api/listings/mine", get(listings_mine))
        .route("/api/pair/start", post(pair_start))
        .route("/api/pair/complete", post(pair_complete))
        .route("/api/pair/delegated", post(pair_delegated))
        .route("/api/agents/checkin", post(agent_checkin))
        .route("/api/handles/start", post(handles_start))
        .route("/api/handles/verify", post(handles_verify))
        .route("/api/handles/session-delegated", post(session_delegated))
        .route("/api/handles/claim", post(handles_claim))
        .route("/api/handles/bind", post(handles_bind))
        .route("/api/handles/release", post(handles_release))
        .route("/api/handles/release-delegated", post(handles_release_delegated))
        .route("/api/handles/rename-window", post(handles_rename_window))
        .route("/api/handles/rehome-out", post(handles_rehome_out))
        .route("/api/handles/rehome-in", post(handles_rehome_in))
        .route("/api/handles/rehome-undo", post(handles_rehome_undo))
        .route("/api/handles/mine", get(handles_mine))
        .route("/api/partner/handles", get(partner_handles))
        .route("/api/partner/release", post(partner_release))
        .route("/api/handles/log", get(handles_log))
        .layer(state_change_cors());

    public.merge(guarded).with_state(pool)
}

/// The CORS policy for state-changing and credentialed routes.
fn state_change_cors() -> tower_http::cors::CorsLayer {
    use tower_http::cors::{AllowOrigin, CorsLayer};
    // Unset means no other origin: the registrar's own pages are same-origin and
    // need no CORS, and an operator names the consoles that may call it.
    let raw = crate::config::allowed_origins().unwrap_or_default();
    if raw.trim() == "*" {
        log::warn!("[pan] PAN_ALLOWED_ORIGINS=* — any web page can drive this registrar's state-changing endpoints");
        return CorsLayer::permissive();
    }
    // Commas or spaces between origins: a space survives every deploy tool's
    // own comma handling.
    let origins: Vec<axum::http::HeaderValue> = raw
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|o| !o.is_empty())
        .filter_map(|o| o.trim().parse().ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(tower_http::cors::Any)
        .allow_headers(tower_http::cors::Any)
}

/// The card-signing key (§5.3), validated ONCE at startup rather than per
/// request. `sign_card` used to return None on any failure — a truncated secret
/// version, a rotation typo — and the response then quietly omitted the
/// signature, which every conforming resolver discards (§5.3). A registrar that
/// cannot sign is not conforming (§7.6), so it says so at startup and refuses
/// to serve resolution rather than serving bytes nobody may act on.
struct CardKey {
    seed: String,
    public: String,
    /// Key id: the first 12 hex digits of sha256 over the public key. Stable
    /// for a key's whole life, so a resolver can pin per key rather than per
    /// registrar and rotation becomes additive instead of a flag day.
    kid: String,
    /// Keys this registrar has retired but still publishes, so a resolver that
    /// pinned one does not see a rotation as tampering (§5.3 pinning).
    retired: Vec<(String, String)>,
}

static CARD_KEY: std::sync::OnceLock<Option<CardKey>> = std::sync::OnceLock::new();

fn kid_for(public: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(public.as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn build_card_key() -> Result<CardKey, String> {
    let seed = std::env::var("PAN_CARD_SEED")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or("PAN_CARD_SEED is not set")?;
    let kp = nkeys::KeyPair::from_seed(&seed)
        .map_err(|e| format!("PAN_CARD_SEED is not a usable nkey seed: {e}"))?;
    // A seed that parses but cannot sign is exactly the failure that used to be
    // invisible, so prove the whole operation once, here.
    kp.sign(b"pan-card-key-selftest")
        .map_err(|e| format!("PAN_CARD_SEED parsed but cannot produce a signature: {e}"))?;
    let public = kp.public_key();
    let retired: Vec<(String, String)> = std::env::var("PAN_CARD_KEYS_RETIRED")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty() && *k != public)
        .filter(|k| nkeys::KeyPair::from_public_key(k).is_ok())
        .map(|k| (kid_for(k), k.to_string()))
        .collect();
    Ok(CardKey { seed, kid: kid_for(&public), public, retired })
}

/// Load and validate the signing key. Returns the public key on success, or a
/// human-readable reason this registrar cannot sign. Call once, from `main`.
pub fn init_card_key() -> Result<String, String> {
    match build_card_key() {
        Ok(key) => {
            let public = key.public.clone();
            let _ = CARD_KEY.set(Some(key));
            Ok(public)
        }
        Err(why) => {
            let _ = CARD_KEY.set(None);
            Err(why)
        }
    }
}

fn card_key() -> Option<&'static CardKey> {
    CARD_KEY.get().and_then(|k| k.as_ref())
}

/// Sign a document (a card or a referral) with the registrar's key. Returns
/// (public key, kid, base64 signature). None only when the registrar has no
/// usable key, which the resolution handlers refuse on rather than paper over.
fn sign_doc(doc: &serde_json::Value) -> Option<(String, String, String)> {
    let key = card_key()?;
    let kp = nkeys::KeyPair::from_seed(&key.seed).ok()?;
    let sig = kp.sign(registrar::canonical_json(doc).as_bytes()).ok()?;
    use base64::Engine as _;
    Some((
        key.public.clone(),
        key.kid.clone(),
        base64::engine::general_purpose::STANDARD.encode(sig),
    ))
}

/// Sign the current chain head, if one is due (§6).
///
/// Returns the commitment written, or None when nothing was due or the
/// registrar cannot issue one. Callable on a timer and idempotent enough to be:
/// `commitment_due` decides, so calling it more often than the cadence costs a
/// query and writes nothing.
///
/// REFUSES RATHER THAN ISSUING A WEAK COMMITMENT in two cases, both of which
/// would produce a signature that says less than it appears to:
///   - no `PAN_SELF_URL`, so the bytes cannot name whose chain they describe and
///     the commitment would be replayable as another registrar's;
///   - no card key, so there is nothing to sign with.
/// An unsigned commitment is not evidence, and a commitment nobody can attribute
/// is not evidence either.
pub async fn commit_log_head(pool: &PgPool) -> Result<Option<registrar::LogCommitment>, String> {
    let Some(me) = self_url() else {
        return Err("PAN_SELF_URL is not set, so a head commitment could not name this registrar".into());
    };
    let Some(key) = card_key() else {
        return Err("no card signing key, so the chain head cannot be committed".into());
    };
    let Some(head) = registrar::current_log_head(pool).await.map_err(|e| e.to_string())? else {
        return Ok(None); // nothing chained yet; there is no head to attest to
    };
    let latest = registrar::latest_log_commitment(pool).await.map_err(|e| e.to_string())?;
    // Truncated to whole seconds BEFORE it is either signed or stored, so the
    // stored value and the signed value are the same value rather than two
    // formattings that have to be kept in agreement. See
    // `at_to_signed_precision` for the bug this prevents.
    use chrono::SubsecRound as _;
    let now = chrono::Utc::now().trunc_subsecs(0);
    if !registrar::commitment_due(latest.as_ref(), &head, &now, commitment_interval_secs()) {
        return Ok(None);
    }
    let canonical = registrar::log_commitment_canonical(&me, &head, &now);
    let kp = nkeys::KeyPair::from_seed(&key.seed)
        .map_err(|e| format!("card seed unusable for signing a commitment: {e}"))?;
    let sig = kp
        .sign(canonical.as_bytes())
        .map_err(|e| format!("could not sign the head commitment: {e}"))?;
    use base64::Engine as _;
    let signature = base64::engine::general_purpose::STANDARD.encode(sig);
    let written = registrar::record_log_commitment(pool, &me, &head, &now, &key.kid, &signature)
        .await
        .map_err(|e| e.to_string())?;
    log::info!(
        "[pan] head commitment {}: {} entries, head {} at seq {}",
        written.id, written.entries, &written.head_hash[..written.head_hash.len().min(12)], written.head_seq
    );
    Ok(Some(written))
}

/// How often a head commitment is issued when the chain is idle. Configurable
/// because the right cadence depends on how much history a deployment has and
/// how often anyone archives it; the default is hourly.
fn commitment_interval_secs() -> i64 {
    std::env::var("PAN_COMMITMENT_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .unwrap_or(3600)
}

/// The one refusal for "this registrar cannot sign, so it will not answer
/// resolution" (§5.3 makes an unsigned card invalid; §7.6 makes signing an
/// obligation).
fn cannot_sign() -> (StatusCode, Json<serde_json::Value>) {
    log::error!("[pan] refusing to serve resolution: no usable card signing key (PAN_CARD_SEED)");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "ok": false,
            "error": "this registrar has no signing key configured, and an unsigned card is invalid (SPEC-NAMING §5.3)"
        })),
    )
}

/// The registrar's mark: a teal badge with an @ — names are what this host
/// does. Served inline so the pure-API deployment needs no static files.
async fn favicon() -> ([(axum::http::HeaderName, &'static str); 1], &'static str) {
    (
        [(axum::http::header::CONTENT_TYPE, "image/svg+xml")],
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>\
         <rect width='64' height='64' rx='14' fill='#0d9488'/>\
         <text x='32' y='44' font-family='monospace' font-weight='700' font-size='34' \
         fill='white' text-anchor='middle'>@</text></svg>",
    )
}

// This host is an API; the page is for the human who lands on it anyway.
async fn ui_index() -> axum::response::Html<String> {
    let name = esc(&crate::config::registrar_name());
    let get = esc(&crate::config::get_a_name_url());
    axum::response::Html(format!(
        "<!doctype html><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">\
         <title>{name}: a Personal Agent Naming registrar</title>\
         <link rel=\"icon\" href=\"/favicon.svg\">\
         <body style=\"font-family:system-ui;max-width:34rem;margin:4rem auto;padding:0 16px;line-height:1.6\">\
         <h1>{name}</h1>\
         <p>This host is a Personal Agent Naming registrar. It gives an agent a name on its owner's \
         email address, binds the name to the agent's key, and answers lookups with a signed card.</p>\
         <p><a href=\"{get}\">Get a name for your agent</a>.</p>\
         <p>The specification: <a href=\"/spec\">/spec</a>, and \
         <a href=\"https://agentnaming.ai\">agentnaming.ai</a>.</p></body>",
    ))
}

/// `/app`: the operator's own console when `PAN_HOME_URL` names one, and
/// otherwise this registrar's claim and pair page.
async fn app_page() -> axum::response::Response {
    use axum::response::IntoResponse;
    match crate::config::home_url() {
        Some(url) => axum::response::Redirect::temporary(&url).into_response(),
        None => (
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            include_str!("../web/app.html").replace("{{REGISTRAR_NAME}}", &esc(&crate::config::registrar_name())),
        )
            .into_response(),
    }
}
/// The spec is a document, not code — it loads from disk (PAN_SPEC_PATH,
/// default ./SPEC-NAMING.md) so editing it never requires a rebuild.
async fn read_spec() -> Result<String, (StatusCode, String)> {
    let path = std::env::var("PAN_SPEC_PATH").unwrap_or_else(|_| "SPEC-NAMING.md".to_string());
    tokio::fs::read_to_string(&path).await.map_err(|e| {
        log::error!("[pan] spec file unreadable at {path}: {e}");
        (StatusCode::INTERNAL_SERVER_ERROR, "spec file missing on this deployment".to_string())
    })
}

/// The PAN spec, rendered. The registrar publishes the protocol it speaks.
async fn spec_page() -> Result<axum::response::Html<String>, (StatusCode, String)> {
    let md = read_spec().await?;
    let parser = pulldown_cmark::Parser::new_ext(&md, pulldown_cmark::Options::all());
    let mut body = String::new();
    pulldown_cmark::html::push_html(&mut body, parser);
    Ok(axum::response::Html(format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="/favicon.svg">
<title>Personal Agent Naming (PAN) · Agent Catalog</title>
<style>
  body {{ background:#0a0e14; color:#e5edf7; font-family:Inter,system-ui,sans-serif;
         line-height:1.65; margin:0; }}
  main {{ max-width:760px; margin:0 auto; padding:2.5rem 1.5rem 5rem; }}
  a {{ color:#d9a441; }} h1,h2,h3 {{ letter-spacing:-.01em; }}
  h1 {{ font-size:2rem; }} h2 {{ margin-top:2.2rem; border-bottom:1px solid #1e2937; padding-bottom:.3rem; }}
  code {{ background:#111722; border:1px solid #1e2937; border-radius:4px; padding:.08em .35em;
          font-family:"JetBrains Mono",ui-monospace,monospace; font-size:.85em; }}
  pre {{ background:#111722; border:1px solid #1e2937; border-radius:8px; padding:.9rem 1rem;
         overflow-x:auto; }} pre code {{ background:none; border:none; padding:0; }}
  table {{ border-collapse:collapse; width:100%; font-size:.9rem; }}
  th,td {{ border:1px solid #1e2937; padding:.45rem .6rem; text-align:left; }}
  blockquote {{ border-left:3px solid #d9a441; margin:0; padding:.1rem 1rem; color:#8695a8; }}
  .top {{ font-size:.85rem; }} hr {{ border:none; border-top:1px solid #1e2937; }}
</style></head><body><main>
<p class="top"><a href="/">← look up a handle</a> · <a href="/spec.md">raw markdown</a></p>
{body}
</main></body></html>"#
    )))
}

async fn spec_raw() -> Result<([(axum::http::HeaderName, &'static str); 1], String), (StatusCode, String)> {
    Ok(([(axum::http::header::CONTENT_TYPE, "text/markdown; charset=utf-8")], read_spec().await?))
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
}

async fn get_one(
    State(pool): State<PgPool>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    match store::get(&pool, id).await.map_err(internal)? {
        Some(listing) => {
            let probes = store::probes_for(&pool, id).await.map_err(internal)?;
            Ok(Json(serde_json::json!({ "ok": true, "listing": listing, "probes": probes })))
        }
        None => Err((StatusCode::NOT_FOUND, "no such listing".to_string())),
    }
}

async fn submit(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<SubmitListing>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Manual submissions carry a verified owner (PAN §4.1) — it's what makes
    // them email-bindable, and it's the public instance's spam control.
    let email = session_from(&pool, &headers).await?;
    if body.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "name is required" })),
        ));
    }
    let id = store::submit(&pool, &body, &email)
        .await
        .map_err(|e| reg_err(e.into()))?;
    match id {
        Some(id) => {
            log::info!("[catalog] manual submission upserted: {} ({id}) by {email}", body.name);
            Ok(Json(serde_json::json!({ "ok": true, "id": id })))
        }
        None => Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "ok": false, "error": "that source_id belongs to another submitter" })),
        )),
    }
}

async fn listings_mine(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let email = session_from(&pool, &headers).await?;
    let listings = store::listings_mine(&pool, &email).await.map_err(|e| reg_err(e.into()))?;
    Ok(Json(serde_json::json!({ "ok": true, "listings": listings })))
}

fn internal(e: sqlx::Error) -> (StatusCode, String) {
    log::error!("[catalog] db error: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ── the registrar: email-anchored handles ──────────────────────────────────

/// Escape text for HTML.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The caller's address, for rate limits and "last connected from".
///
/// `X-Forwarded-For` is believed only when the connection itself comes from a
/// proxy the operator trusts (`PAN_TRUSTED_PROXIES`, `LB_PUBLIC_IPS`). Then the
/// header is read from the RIGHT, the entries the proxies appended, skipping
/// every trusted proxy, and the first address that is not one of them is the
/// caller; anything a client planted sits further left and is never reached
/// first. With no trusted proxy, or a connection from anywhere else, the header
/// is ignored and the caller is the socket peer. A registrar run with nothing in
/// front of it therefore cannot be talked out of its own rate limits by a header.
fn client_ip(headers: &HeaderMap, peer: Option<std::net::SocketAddr>) -> Option<String> {
    client_ip_with(headers, peer, &crate::config::trusted_proxies())
}

fn client_ip_with(
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    trusted: &[crate::config::Cidr],
) -> Option<String> {
    let is_trusted = |ip: &std::net::IpAddr| trusted.iter().any(|c| c.contains(ip));
    let peer_ip = peer.map(|p| p.ip());
    // A Cloud Run or similar front end hands the connection over from an
    // address that is itself one of the trusted ranges; a bare connection from a
    // client is not, and its header is the client's own words.
    let from_proxy = match peer_ip {
        Some(ip) => is_trusted(&ip),
        None => true,
    };
    if from_proxy && !trusted.is_empty() {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            for part in xff.split(',').rev() {
                if let Ok(ip) = part.trim().parse::<std::net::IpAddr>() {
                    if !is_trusted(&ip) {
                        return Some(ip.to_string());
                    }
                }
            }
        }
    }
    peer_ip.map(|ip| ip.to_string())
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;
    use crate::config::parse_cidrs;

    fn headers(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", xff.parse().unwrap());
        h
    }
    fn peer(ip: &str) -> Option<std::net::SocketAddr> {
        Some(std::net::SocketAddr::new(ip.parse().unwrap(), 4000))
    }

    #[test]
    fn with_no_trusted_proxy_the_header_is_ignored() {
        let got = client_ip_with(&headers("203.0.113.44"), peer("203.0.113.9"), &[]);
        assert_eq!(got.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn a_client_outside_the_trusted_ranges_cannot_choose_its_address() {
        let trusted = parse_cidrs("10.0.0.0/8, 198.51.100.0/24");
        let got = client_ip_with(&headers("203.0.113.44"), peer("203.0.113.9"), &trusted);
        assert_eq!(got.as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn behind_a_trusted_proxy_the_rightmost_untrusted_entry_is_the_caller() {
        let trusted = parse_cidrs("198.51.100.0/24 192.0.2.80 169.254.0.0/16");
        // A planted entry on the left, the real client, then the load balancer
        // and the front end the platform appended.
        let got = client_ip_with(
            &headers("203.0.113.66, 203.0.113.7, 192.0.2.80, 198.51.100.5"),
            peer("169.254.1.1"),
            &trusted,
        );
        assert_eq!(got.as_deref(), Some("203.0.113.7"));
    }
}

fn reg_err(e: RegistrarError) -> (StatusCode, Json<serde_json::Value>) {
    let (code, msg) = match &e {
        RegistrarError::Invalid(m) => (StatusCode::BAD_REQUEST, m.clone()),
        RegistrarError::Taken(m) => (StatusCode::CONFLICT, m.clone()),
        RegistrarError::TooMany(m) => (StatusCode::TOO_MANY_REQUESTS, m.clone()),
        RegistrarError::Unauthorized => {
            (StatusCode::UNAUTHORIZED, "session expired — verify your email again".to_string())
        }
        RegistrarError::Forbidden(m) => (StatusCode::FORBIDDEN, m.clone()),
        RegistrarError::Db(err) => {
            log::error!("[pan] db error: {err}");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage error".to_string())
        }
    };
    (code, Json(serde_json::json!({ "ok": false, "error": msg })))
}

async fn session_from(
    pool: &PgPool,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|v| Uuid::parse_str(v.trim()).ok())
        .ok_or_else(|| reg_err(RegistrarError::Unauthorized))?;
    registrar::session_email(pool, token).await.map_err(reg_err)
}

/// Like `session_from`, but also returns the session's provenance
/// ('email' or 'delegated:<partner>'), for scope-gated endpoints.
async fn session_info_from(
    pool: &PgPool,
    headers: &HeaderMap,
) -> Result<(String, String), (StatusCode, Json<serde_json::Value>)> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|v| Uuid::parse_str(v.trim()).ok())
        .ok_or_else(|| reg_err(RegistrarError::Unauthorized))?;
    registrar::session_info(pool, token).await.map_err(reg_err)
}

/// Branded HTML for the verification email. Mirrors the shared account-email
/// look in `services/src/api/email.ts` (`shell()`): a white card on a soft page,
/// the "AGENTMESH" eyebrow, a heading, the code in a large monospace block, and
/// the plain-text footer. Kept in sync by hand because the two services share no
/// code (this registrar is Rust, the account service is TypeScript). Inline
/// styles only, so it survives every mail client; the `text` field is the
/// fallback. Colors and fonts are copied from that module verbatim.
fn verification_email_html(code: &str, email: &str) -> String {
    let email = email
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>Your verification code</title>
</head>
<body style="margin:0;padding:0;background:#F2F6F4;-webkit-text-size-adjust:100%;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F2F6F4;">
    <tr><td align="center" style="padding:32px 12px;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:512px;background:#FFFFFF;border:1px solid #DCE6E2;border-radius:6px;">
        <tr><td style="padding:30px 32px 0;font-family:{font};">
          <div style="font-family:{mono};font-size:11px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;color:#0E6B57;">{brand}</div>
          <h1 style="margin:14px 0 0;font-family:{font};font-size:21px;line-height:1.25;font-weight:600;letter-spacing:-.01em;color:#0A1417;">Your verification code</h1>
        </td></tr>
        <tr><td style="padding:14px 32px 4px;font-family:{font};font-size:15px;line-height:1.65;color:#33453F;">
          Enter this code to verify <strong style="color:#0A1417;font-weight:600;">{email}</strong>. It expires in 15 minutes.
        </td></tr>
        <tr><td style="padding:10px 32px 6px;">
          <div style="padding:16px 20px;background:#F2F6F4;border:1px solid #DCE6E2;border-radius:5px;font-family:{mono};font-size:30px;font-weight:600;letter-spacing:.28em;color:#0A1417;text-align:center;">{code}</div>
        </td></tr>
        <tr><td style="padding:12px 32px 28px;font-family:{font};font-size:13px;line-height:1.6;color:#5A6E69;">
          If you didn't request this, you can ignore this email.
        </td></tr>
        <tr><td style="padding:0 32px;"><div style="height:1px;background:#DCE6E2;line-height:1px;font-size:0;">&nbsp;</div></td></tr>
        <tr><td style="padding:18px 32px 24px;font-family:{font};font-size:12px;line-height:1.6;color:#5A6E69;">
          {footer_line}<br>
          Sent from an address that cannot receive replies.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"#,
        font = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif",
        mono = "ui-monospace,SFMono-Regular,'SF Mono',Menlo,Consolas,monospace",
        email = email,
        code = code,
        brand = esc(&crate::config::registrar_name()),
        footer_line = match crate::config::self_url() {
            Some(u) => format!(
                "{} &middot; <a href=\"{}\" style=\"color:#0E6B57;text-decoration:none;\">{}</a>",
                esc(&crate::config::registrar_name()),
                esc(&u),
                esc(u.trim_start_matches("https://").trim_start_matches("http://"))
            ),
            None => esc(&crate::config::registrar_name()),
        },
    )
}

/// Deliver a verification code by the deployment's mail provider (see
/// `mail.rs`), or to the log in development mode. The response says which
/// delivery happened.
async fn deliver_code(email: &str, code: &str) -> &'static str {
    let name = crate::config::registrar_name();
    crate::mail::send(
        crate::mail::Message {
            to: email,
            subject: format!("{code} is your {name} verification code"),
            text: format!(
                "Your verification code is {code}. It expires in 15 minutes.

                 If you didn't request this, ignore this email.

{}",
                crate::mail::footer_text()
            ),
            html: Some(verification_email_html(code, email)),
        },
        "verification code",
        true,
    )
    .await
}

#[derive(Deserialize)]
struct StartBody {
    email: String,
}

async fn handles_start(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<StartBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Unauthenticated and it sends mail from this registrar's domain, so the
    // per-anchor limit inside start_verification is only one of three ceilings
    // (per caller address and service-wide are the others) — rotating
    // recipients was otherwise an unbounded send.
    let ip = client_ip(&headers, Some(peer)).unwrap_or_else(|| "unknown".into());
    let (email, code) = registrar::start_verification(&pool, &body.email, &ip).await.map_err(reg_err)?;
    let delivery = deliver_code(&email, &code).await;
    Ok(Json(serde_json::json!({ "ok": true, "email": email, "delivery": delivery })))
}

#[derive(Deserialize)]
struct VerifyBody {
    email: String,
    code: String,
}

async fn handles_verify(
    State(pool): State<PgPool>,
    Json(body): Json<VerifyBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let token = registrar::verify_code(&pool, &body.email, &body.code).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "token": token })))
}

// ---------------------------------------------------------------------------
// Two shared secrets, because they are two authorities
// ---------------------------------------------------------------------------
//
// SPEC-NAMING describes two powers a deployment can hold, and they are not the
// same power:
//
//   WITNESSING (§3.1, `PAN_DELEGATE_SECRET`). A partner platform says it has
//   already verified a member's email, and gets a session for THAT ONE anchor
//   (`POST /api/handles/session-delegated`). Everything the session can then do
//   is bounded by the anchor: claim under it, bind under it, release the handles
//   it holds. This is the ordinary integration credential — the one that lives
//   in another service's configuration and gets used on every signup.
//
//   MODERATION (§9, `PAN_OPERATOR_SECRET`). The registrar operator acting on the
//   namespace itself. `GET /api/partner/handles` reads any anchor's roster and
//   `POST /api/partner/release` takes down any handle regardless of owner —
//   there is no anchor check on either, because moderation IS the power to act
//   on names that are not yours.
//
// Until now one secret authorized both, and that cost two things. A leaked
// partner integration secret was also a namespace moderation key. And an access
// log could not tell a partner acting for its own member apart from an operator
// acting on anybody: same secret, same header, and the only difference was which
// route the holder happened to call. §9 SHOULDs the credentials apart so the two
// authorities can fail separately, and §3.1 repeats it for any registrar that
// accepts delegated release. That is what this does.
//
// BACKWARD COMPATIBILITY, deliberately. The deployed configuration sets only
// `PAN_DELEGATE_SECRET`, so requiring the new one would take moderation offline
// on the next deploy — including the account-closure path in `services/` — to
// improve a property that no request depends on. Instead the moderation routes
// use `PAN_OPERATOR_SECRET` when it is set and fall back to the witnessing
// secret when it is not, and the fallback says so loudly at every startup. The
// deployment is then exactly as safe as it is today until an operator splits the
// secrets, and it is told at every boot that it has not.

/// How this deployment's moderation credential is configured. Reported at
/// startup and attached to every moderation action in the log, because "which
/// authority was this" is the question the split exists to make answerable.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SecretSplit {
    /// `PAN_OPERATOR_SECRET` is set and differs from the witnessing secret.
    /// What §9 asks for: a leaked partner credential is not a moderation key.
    Separate,
    /// `PAN_OPERATOR_SECRET` is unset. Moderation falls back to the witnessing
    /// secret — the pre-split deployment, still working, still warned about.
    FellBackToWitness,
    /// Both are set, to the same bytes. This is the configuration that looks
    /// split and is not, which is worse than the honest fallback: an operator
    /// reading the deployment believes the split happened.
    SetIdentically,
    /// Neither is set. Delegation and moderation are both off.
    Unconfigured,
}

/// The moderation credential and how the deployment arrived at it. Pure, so the
/// precedence and the two dishonest-looking cases are unit-testable without a
/// process environment.
fn moderation_secret_from(
    operator: Option<&str>,
    witness: Option<&str>,
) -> (SecretSplit, Option<String>) {
    match (operator, witness) {
        (Some(op), Some(w)) if op == w => (SecretSplit::SetIdentically, Some(op.to_string())),
        (Some(op), _) => (SecretSplit::Separate, Some(op.to_string())),
        (None, Some(w)) => (SecretSplit::FellBackToWitness, Some(w.to_string())),
        (None, None) => (SecretSplit::Unconfigured, None),
    }
}

/// A configured secret, or None. Empty counts as unset — an env var set to ""
/// is a deployment mistake, not a credential that authorizes an empty header.
///
/// Deliberately NOT trimmed: the expected value is compared byte-for-byte
/// against what a caller sends, and trimming one side of that comparison would
/// break every caller whose stored secret ends in the newline a secret store
/// added for it.
fn env_secret(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.is_empty())
}

fn moderation_secret() -> (SecretSplit, Option<String>) {
    moderation_secret_from(
        env_secret("PAN_OPERATOR_SECRET").as_deref(),
        env_secret("PAN_DELEGATE_SECRET").as_deref(),
    )
}

/// Constant-time comparison, so a wrong secret leaks no length or timing signal.
fn secret_matches(provided: &str, expected: &str) -> bool {
    let a = provided.as_bytes();
    let b = expected.as_bytes();
    a.len() == b.len() && a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn not_configured(what: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({ "ok": false, "error": format!("{what} not configured") })),
    )
}

fn bad_secret(which: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "ok": false, "error": format!("invalid {which} secret") })),
    )
}

/// The witnessing credential (§3.1): `PAN_DELEGATE_SECRET` in `x-delegate-secret`.
/// Unchanged, including the header, because a partner integration holds it.
fn require_witness_secret(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let expected = env_secret("PAN_DELEGATE_SECRET").ok_or_else(|| not_configured("delegation"))?;
    let provided = headers.get("x-delegate-secret").and_then(|v| v.to_str().ok()).unwrap_or("");
    if secret_matches(provided, &expected) {
        Ok(())
    } else {
        Err(bad_secret("delegate"))
    }
}

/// The moderation credential (§9), for `/api/partner/*`. Returns how the
/// deployment is configured so the route can say so in its own log line.
///
/// Two headers are accepted, and that is the migration path rather than
/// sloppiness. `x-operator-secret` is what a split deployment should send. But
/// the caller that exists today sends `x-delegate-secret`, and it is owned by
/// another service and deployed separately, so an operator must be able to split
/// the secrets here FIRST — set `PAN_OPERATOR_SECRET`, hand that value to the
/// caller — without a synchronized header change. What matters is the value: once
/// `PAN_OPERATOR_SECRET` is set, a holder of only the witnessing secret is
/// refused no matter which header it arrives in, which is the whole property.
fn require_moderation_secret(
    headers: &HeaderMap,
) -> Result<SecretSplit, (StatusCode, Json<serde_json::Value>)> {
    let (split, expected) = moderation_secret();
    let expected = expected.ok_or_else(|| not_configured("moderation"))?;
    let provided = headers
        .get("x-operator-secret")
        .or_else(|| headers.get("x-delegate-secret"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if secret_matches(provided, &expected) {
        Ok(split)
    } else {
        Err(bad_secret("operator"))
    }
}

/// What an operator needs to know about these two secrets at startup, said where
/// the other quietly-failing settings are already said (`main`).
///
/// The shared cases WARN rather than refusing to boot. Refusing would turn a
/// configuration that is no less safe than the one running in production today
/// into a total outage of resolution, claiming and pairing — the whole registrar
/// — over a property that no single request depends on. The dishonest case
/// (`SetIdentically`) gets the loudest wording available, because unlike the
/// plain fallback it looks finished.
pub fn report_credential_split() {
    match moderation_secret().0 {
        SecretSplit::Separate => log::info!(
            "[pan] credentials are separate: PAN_DELEGATE_SECRET witnesses (SPEC-NAMING §3.1), \
             PAN_OPERATOR_SECRET moderates (§9). A leaked partner integration secret is not a \
             namespace moderation key."
        ),
        SecretSplit::FellBackToWitness => log::warn!(
            "[pan] PAN_OPERATOR_SECRET is not set: the moderation routes (POST \
             /api/partner/release, GET /api/partner/handles) fall back to PAN_DELEGATE_SECRET. \
             SPEC-NAMING §9 asks for these credentials to be SEPARATE, and while they are not: a \
             leaked partner integration secret is also a namespace moderation key that can release \
             ANY handle of ANY owner irreversibly (§3 cooling-off, §5.6 no re-issue), and no access \
             log distinguishes a partner acting for its own member from an operator acting on \
             anyone. FIX: set PAN_OPERATOR_SECRET to a fresh value and give that value, not the \
             delegate secret, to whoever performs moderation."
        ),
        SecretSplit::SetIdentically => log::error!(
            "[pan] MISCONFIGURED: PAN_OPERATOR_SECRET and PAN_DELEGATE_SECRET are set to the SAME \
             value. This deployment looks like it separated the witnessing and moderation \
             credentials (SPEC-NAMING §3.1, §9) and did not: one secret still authorizes both, so \
             one leak still hands over namespace moderation, and the record still cannot tell the \
             two authorities apart. It is worse than leaving PAN_OPERATOR_SECRET unset, because \
             that at least reads as unfinished. FIX: rotate PAN_OPERATOR_SECRET to a value the \
             partner integration does not hold."
        ),
        SecretSplit::Unconfigured => log::info!(
            "[pan] neither PAN_DELEGATE_SECRET nor PAN_OPERATOR_SECRET is set: delegated \
             sessions (§3.1) and the operator moderation routes are both disabled (501)."
        ),
    }
}

#[derive(Deserialize)]
struct DelegatedBody {
    email: String,
}

/// Delegated verification (trusted server-to-server): a partner service that
/// has already verified the user's email — the AgentMesh control plane, whose
/// account session proves the same email (core §4.9) — mints a PAN session
/// without a second email round trip, then claims/binds a name on the user's
/// behalf. Authorized by a shared secret in `X-Delegate-Secret`, NOT a user
/// session. Disabled unless `PAN_DELEGATE_SECRET` is set. The name stays a
/// normal PAN handle: portability and the direct two-service path are unchanged.
///
/// This is the WITNESSING credential only. It does not authorize
/// `/api/partner/*`, which is moderation (§9) and takes `PAN_OPERATOR_SECRET`
/// where a deployment has set one.
async fn session_delegated(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<DelegatedBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    require_witness_secret(&headers)?;
    let partner =
        std::env::var("PAN_DELEGATE_PARTNER").unwrap_or_else(|_| "partner".to_string());
    let token =
        registrar::mint_session_as(&pool, &body.email, &format!("delegated:{partner}"))
            .await
            .map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "token": token })))
}

#[derive(Deserialize)]
struct ClaimBody {
    name: String,
    #[serde(default)]
    listing_id: Option<Uuid>,
    /// PAN v0.3: every operator has a required public display name. Provide
    /// it here on (at least) the first claim; later claims inherit it.
    #[serde(default)]
    operator_name: Option<String>,
}

async fn handles_claim(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<ClaimBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    // A partner claims on its users' behalf, from names it proposes, so its
    // claims keep to the partner name rule (slug.rs): one shape a person can
    // read aloud and type back, and a handle that splits one way only. A
    // person signed in here directly keeps the full §2 grammar.
    if provenance != "email" && !crate::slug::is_name_slug(body.name.trim()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "ok": false,
                "error": "a name claimed through a partner is 1 to 32 characters: lowercase letters, digits and hyphens, starting and ending with a letter or digit"
            })),
        ));
    }
    // §3 requires an operator record no later than the anchor's first claim, so
    // the name is CHECKED before the claim and WRITTEN after it: setting it
    // first meant a claim that then failed (taken, cooling off, re-homed away)
    // had already renamed the operator on every card of that anchor's handles.
    match body.operator_name.as_deref() {
        Some(n) => {
            registrar::validate_operator_name(n).map_err(reg_err)?;
        }
        None if registrar::operator_get(&pool, &email).await.map_err(reg_err)?.is_none() => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "ok": false,
                    "error": "operator_name required: PAN requires a public display name for the operator (your chosen label, shown on your handles' cards)"
                })),
            ));
        }
        None => {}
    }
    let handle = registrar::claim(&pool, &email, &body.name, body.listing_id, &provenance)
        .await
        .map_err(reg_err)?;
    if let Some(ref n) = body.operator_name {
        registrar::operator_set(&pool, &email, n).await.map_err(reg_err)?;
    }
    Ok(Json(serde_json::json!({ "ok": true, "handle": handle })))
}

#[derive(Deserialize)]
struct BindBody {
    handle: String,
    #[serde(default)]
    listing_id: Option<Uuid>,
}

async fn handles_bind(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<BindBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    // Binding to a listing is establishing (§3.1, §4.3): a delegated session
    // may do it. Binding to NOTHING is destroying — it detaches the handle,
    // and every agent under that anchor stops resolving to an address. §3.1
    // gives a delegated session no such power, and §9 concedes only squatting
    // and rebinding from a stolen delegate credential, never unbinding.
    if body.listing_id.is_none() && provenance != "email" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "a delegated session cannot detach a handle from its agent; sign in directly at the registrar to unbind"
            })),
        ));
    }
    registrar::bind(&pool, &email, &body.handle, body.listing_id).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
struct PairDelegatedBody {
    handle: String,
    agent_id: String,
    /// The owner reports the key this binding replaces as leaked (SPEC.md
    /// §5.3): recorded on the key change as `old_key_revoked`. Absent means
    /// false, which is every binding before this field existed.
    #[serde(default)]
    revoke_previous: bool,
}

/// Delegated binding (§4.3): only a delegated session may call this — the
/// partner is the witness of agent-key control, having verified it
/// first-hand by an equivalent signed ceremony. Directly signed-in owners
/// pair via /api/pair/start + /api/pair/complete instead.
async fn pair_delegated(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<PairDelegatedBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    let Some(partner) = provenance.strip_prefix("delegated:").map(str::to_string) else {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "delegated binding requires a delegated session; use pair/start and pair/complete when signed in directly"
            })),
        ));
    };
    let handle = registrar::pair_delegated(&pool, &email, &partner, &body.handle, &body.agent_id, body.revoke_previous)
        .await
        .map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "handle": handle })))
}

#[derive(Deserialize)]
struct ReleaseBody {
    handle: String,
}

/// POST /api/handles/release — the owner, having proved the mailbox, gives up a
/// name. Unchanged: this route means one thing, "the anchor itself asked", and a
/// delegated session is still not that. A partner acting for its own user has
/// `release-delegated` below; the refusal names it, because the old message sent
/// a partner service to "sign in directly", which it cannot do, and the only
/// route it could then find was the operator's moderation lever.
async fn handles_release(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<ReleaseBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    // Delegated sessions establish; only a directly verified owner destroys.
    if provenance != "email" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "this route releases on the anchor's own proof; sign in directly at the registrar, \
                          or, for a partner releasing a handle of the anchor its session speaks for, \
                          POST /api/handles/release-delegated"
            })),
        ));
    }
    registrar::release(&pool, &email, &body.handle).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// POST /api/handles/release-delegated (§3.1) — a delegated session gives up a
/// handle of ITS OWN anchor. For the case the account-closure cascade actually
/// is: the person asked their platform to close their account, and the names
/// anchored to that account have to go with it.
///
/// WHY THIS IS NOT `partner/release`. That route is the operator's
/// namespace-moderation lever: it is authorized by `PAN_OPERATOR_SECRET`, it
/// releases any handle by name regardless of owner, and it writes
/// `released_by_operator` into an append-only log. Pointing a user-initiated
/// closure at it was wrong twice over — it put the operator's moderation
/// authority behind an ordinary user action, and it recorded the operator as
/// having taken a name its owner gave up. §9 requires operator-initiated releases
/// to be logged as such, which only means anything if releases that were not
/// operator-initiated are not.
///
/// WHY IT IS A SEPARATE ROUTE and not a relaxation of the one above. The two do
/// not share an authorization rule. `handles/release` means "the anchor proved
/// control of its mailbox"; this means "a partner the registrar chose asserts it
/// is acting for that anchor" — §3.1's trust link, one hop further from the
/// person. Folding them together would give one route two proofs behind a
/// conditional and would leave nothing to name in the spec, in an access log, or
/// at the router if a delegate credential is ever suspected. Separate routes keep
/// one rule each, and keep the refusal above true as written.
///
/// WHAT THIS DOES AND DOES NOT BUY, plainly. A delegated session's anchor is
/// chosen by whoever holds the witnessing secret, so the anchor test below is not
/// a barrier to that holder — it picks the anchor when it mints the session. What
/// the test buys is that a caller cannot release a handle it did not mean to,
/// that the failure is a 403 saying so rather than a silent no-op, and that the
/// two authorities do not share a route.
///
/// What bounds a STOLEN witnessing credential is the other half, and it now
/// exists: `partner/release` takes `PAN_OPERATOR_SECRET`, so on a deployment that
/// set one, this route's anchor test is the only release a stolen §3.1 credential
/// can reach — one anchor at a time, each one logged under a named anchor and a
/// named partner. On a deployment that did NOT set one, moderation still falls
/// back to the witnessing secret and the stolen credential still releases
/// anything; that deployment is warned at every boot.
async fn handles_release_delegated(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<ReleaseBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    // Same gate shape as pair_delegated (§4.3): the provenance IS the credential
    // here, and a directly verified owner is deliberately sent to the plain route
    // so a `released` entry's `via` is never guesswork.
    if provenance.strip_prefix("delegated:").is_none() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "this route requires a delegated session; a directly verified owner releases at POST /api/handles/release"
            })),
        ));
    }
    // Refused on the strings, before storage: a handle is `<name>.<anchor>` (§2),
    // so a request for somebody else's name is answerable without a lookup, and a
    // refusal that looked nothing up cannot report whether the name exists.
    if !registrar::handle_anchors_to(&body.handle, &email) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "that handle is not anchored to the email this session speaks for; a delegated session may only release its own anchor's handles"
            })),
        ));
    }
    let released = registrar::release_by_anchor(&pool, &email, &body.handle, &provenance)
        .await
        .map_err(reg_err)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "handle": released.handle,
        "released_at": released.released_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "claimable_after": released.claimable_after.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })))
}

#[derive(Deserialize)]
struct PartnerHandlesQuery {
    email: String,
}

/// Operator lookup (the MODERATION credential, §9): ALL handles under an email,
/// with bound agent keys — the platform operator's view of its own members. The
/// public `/api/discover` keeps honoring the discoverable flag; this endpoint is
/// for the party that already runs the registrar's front door.
///
/// It reads any anchor's roster with no anchor check, which is why it takes
/// `PAN_OPERATOR_SECRET` (in `x-operator-secret`, or `x-delegate-secret` while a
/// deployment is mid-split) rather than the §3.1 witnessing secret.
async fn partner_handles(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(q): Query<PartnerHandlesQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let split = require_moderation_secret(&headers)?;
    log::info!(
        "[pan] operator roster read for {} (moderation credential: {split:?})",
        q.email.trim().to_lowercase()
    );
    let handles = registrar::mine(&pool, &q.email.trim().to_lowercase()).await.map_err(reg_err)?;
    let mut rows: Vec<serde_json::Value> = Vec::new();
    for h in &handles {
        let agent_id = match h.listing_id {
            Some(id) => store::get(&pool, id).await.map_err(|e| reg_err(e.into()))?.map(|l| l.source_id),
            None => None,
        };
        rows.push(serde_json::json!({
            "handle": h.handle,
            "bound": h.listing_id.is_some(),
            "agent_id": agent_id,
            "claimed_via": h.claimed_via,
            "created_at": h.created_at,
        }));
    }
    Ok(Json(serde_json::json!({ "ok": true, "email": q.email, "handles": rows })))
}

#[derive(Deserialize)]
struct PartnerReleaseBody {
    handle: String,
}

/// Operator release (the MODERATION credential, §9): revoke a handle by name,
/// regardless of owner — the namespace-moderation lever. The public
/// self-service release still requires the owner's session; this is the
/// operator taking a name down for cause, and it returns the former owner so
/// the caller can audit-log it.
///
/// The most destructive route this service has: it releases ANY handle of ANY
/// owner, and a release is irreversible (§3 cooling-off, and §5.6 bars re-issue).
/// It takes `PAN_OPERATOR_SECRET`, so a leaked partner integration secret is not
/// a key to it — provided the deployment set one, which is what the startup
/// warning is about.
async fn partner_release(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<PartnerReleaseBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let split = require_moderation_secret(&headers)?;
    // Said before the act, and at warn level: on a deployment that has not split
    // its secrets this line is the only place the record admits that the caller
    // MIGHT have been a partner holding the witnessing secret rather than the
    // operator. `release_any` writes `released_by_operator` either way.
    log::warn!(
        "[pan] OPERATOR RELEASE requested for {} (moderation credential: {split:?})",
        body.handle.trim()
    );
    let email = registrar::release_any(&pool, body.handle.trim()).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "handle": body.handle, "former_owner": email })))
}

async fn handles_mine(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let email = session_from(&pool, &headers).await?;
    let handles = registrar::mine(&pool, &email).await.map_err(reg_err)?;
    // Owner-only provenance: attach "last connected from" per bound handle.
    // This never appears on the public card (resolve/build_card).
    let ids: Vec<Uuid> = handles.iter().filter_map(|h| h.listing_id).collect();
    let seen = registrar::last_seen_ips(&pool, &ids).await.map_err(reg_err)?;
    let rows: Vec<serde_json::Value> = handles
        .iter()
        .map(|h| {
            let mut v = serde_json::to_value(h).unwrap_or_default();
            if let (Some(id), Some(obj)) = (h.listing_id, v.as_object_mut()) {
                if let Some((ip, at, kind, host, platform, first, enc_key)) = seen.get(&id) {
                    obj.insert("last_seen_ip".into(), serde_json::json!(ip));
                    obj.insert("last_seen_ip_at".into(), serde_json::json!(at));
                    obj.insert("agent_kind".into(), serde_json::json!(kind));
                    obj.insert("agent_host".into(), serde_json::json!(host));
                    obj.insert("agent_platform".into(), serde_json::json!(platform));
                    obj.insert("first_connected_at".into(), serde_json::json!(first));
                    obj.insert("encryption_key".into(), serde_json::json!(enc_key));
                }
            }
            v
        })
        .collect();
    Ok(Json(serde_json::json!({ "ok": true, "email": email, "handles": rows })))
}

#[derive(Deserialize)]
struct PairStartBody {
    handle: String,
}

async fn pair_start(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<PairStartBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let email = session_from(&pool, &headers).await?;
    let (code, expires_at) =
        registrar::pair_start(&pool, &email, &body.handle).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "code": code, "expires_at": expires_at })))
}

#[derive(Deserialize)]
struct PairCompleteBody {
    code: String,
    agent_id: String,
    signature: String,
}

/// Unauthenticated by design (PAN §4.2): code + agent-key signature are the
/// two proofs, and the binding is their intersection.
async fn pair_complete(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PairCompleteBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Unauthenticated, and it takes a guessable-length code: 32^6 over ten
    // minutes is far out of reach by search, but there was no attempt cap at
    // all, and an uncapped endpoint is how a code space gets searched anyway.
    let ip = client_ip(&headers, Some(peer)).unwrap_or_else(|| "unknown".into());
    let limit = registrar::limit_from_env("PAN_PAIR_MAX_PER_IP_HOUR", 60);
    if !registrar::rate_ok(&pool, &format!("pair:{ip}"), limit, 3600).await.map_err(reg_err)? {
        return Err(too_many_of("pairing attempts"));
    }
    let handle = registrar::pair_complete(&pool, &body.code, &body.agent_id, &body.signature)
        .await
        .map_err(reg_err)?;
    // Owner-facing provenance: the pairing request comes from the agent's own
    // machine, so its source IP is "last connected from".
    if ip != "unknown" {
        registrar::record_agent_seen(&pool, &body.agent_id, &ip, &Default::default())
            .await
            .map_err(reg_err)?;
    }
    Ok(Json(serde_json::json!({ "ok": true, "handle": handle })))
}

#[derive(Deserialize)]
struct RehomeBody {
    handle: String,
    agent_id: String,
    timestamp: String,
    signature: String,
    /// The destination registrar — the value the statement signed over. Both
    /// custodians verify against this same string (§5.6).
    new_registrar: String,
    /// The source registrar, for the new custodian's `rehomed:<old>` provenance.
    #[serde(default)]
    old_registrar: String,
    /// Which email anchors the handle. Needed on the way in only when the
    /// handle reads more than one way (a dot in the name, or in the email's
    /// local part); a handle with one dot before the '@' reads one way.
    #[serde(default)]
    anchor: Option<String>,
}

/// Both re-home routes are unauthenticated (the agent-key signature is the
/// authority, as with pairing), which makes them the one pair of endpoints
/// that create handle and listing rows for a caller who never proved anything
/// to us first. A per-IP cap keeps that from being a way to flood the
/// namespace. Re-homing is a rare, human-driven act, so the ceiling is set far
/// above real use; the real gate on migration IN is corroboration from the
/// losing registrar, and this is depth behind it. Raise it via
/// PAN_REHOME_MAX_PER_HOUR for a test rig, which re-homes in a tight loop.
fn rehome_max_per_hour() -> i64 {
    registrar::limit_from_env("PAN_REHOME_MAX_PER_HOUR", 60)
}

/// The ceiling lives in the database, not in this process: Cloud Run runs
/// several instances, and an in-process counter's real limit is the configured
/// one times however many are warm.
async fn rehome_rate_ok(pool: &PgPool, ip: &str) -> bool {
    registrar::rate_ok(pool, &format!("rehome:{ip}"), rehome_max_per_hour(), 3600)
        .await
        .unwrap_or(true)
}

fn too_many() -> (StatusCode, Json<serde_json::Value>) {
    too_many_of("re-home requests")
}

/// One shape for every ceiling: say what was too much, never how close the
/// caller is to the limit.
fn too_many_of(what: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({ "ok": false, "error": format!("too many {what} — try again later") })),
    )
}

/// This registrar's own public URL. A re-home statement names its destination,
/// so the destination has to know its own name to check it — and if it does
/// not, it must not take custody of anything. Fail closed: an unset
/// PAN_SELF_URL disables migration IN rather than silently accepting
/// statements written for somebody else.
fn self_url() -> Option<String> {
    std::env::var("PAN_SELF_URL").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Migration OUT (§5.6/§7.8): the current custodian records a key-signed
/// departure. Unauthenticated by design — the agent-key signature is the
/// authority, exactly like pairing.
async fn handles_rehome_out(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<RehomeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip = client_ip(&headers, Some(peer)).unwrap_or_else(|| "unknown".into());
    if !rehome_rate_ok(&pool, &ip).await {
        return Err(too_many());
    }
    let moved =
        registrar::rehome_out(&pool, &b.handle, &b.new_registrar, &b.agent_id, &b.timestamp, &b.signature)
            .await
            .map_err(reg_err)?;
    // A move is authorized by the agent key alone, so the person who proved the
    // mailbox never hears about it — and the undo window is worth nothing to
    // someone who does not know the clock started. Best effort: a failed send
    // must not fail a move the spec says a registrar cannot refuse (§7.8).
    notify_rehome(&moved).await;
    Ok(Json(serde_json::json!({
        "ok": true,
        "handle": moved.handle,
        "rehomed_to": moved.new_registrar,
        "undo_until": moved.undo_until,
    })))
}

/// Tell the anchor owner their name left, and by when they can reverse it.
async fn notify_rehome(moved: &registrar::RehomedOut) {
    let text = format!(
        "The name {} was moved to another naming registrar ({}).

         The move was authorized by a signature from the agent key the name is bound to.          If that was you or your agent's software, nothing more is needed.

         If it was not, you can reverse it until {} by signing in to the registrar with this          email address and undoing the move.

{}",
        moved.handle,
        moved.new_registrar,
        moved.undo_until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        crate::mail::footer_text(),
    );
    crate::mail::send(
        crate::mail::Message {
            to: &moved.anchor,
            subject: "Your agent name moved to another registrar".to_string(),
            text,
            html: None,
        },
        "re-home notice",
        false,
    )
    .await;
}

#[derive(Deserialize)]
struct RehomeUndoBody {
    handle: String,
    /// Lift the post-undo hold instead of reversing a move: for an owner who
    /// undid one move and now does want to re-home on purpose.
    #[serde(default)]
    resume: bool,
}

/// POST /api/handles/rehome-undo — the anchor owner's say in a move (§5.6).
///
/// Re-homing is key-authorized by design: §5.6 has the key sign, and §7.8 says
/// a registrar that will not let a name leave is not conforming. That leaves the
/// mailbox owner — the party §3 anchors the name to — with no part in a move
/// that is permanent and irreversible. Requiring an email session on the way
/// OUT would contradict both sections (and would strand an owner whose mailbox
/// is gone), so the owner's standing is here instead: a bounded window in which
/// the anchor, proved directly, can put the name back.
async fn handles_rehome_undo(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(b): Json<RehomeUndoBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    // Reversing a move is not establishing (§3.1): a delegated partner's
    // attestation is not the owner's word about where their name lives.
    if provenance != "email" {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "ok": false,
                "error": "reversing a re-home requires signing in directly at the registrar with the anchor email"
            })),
        ));
    }
    let handle = registrar::rehome_undo(&pool, &email, &b.handle, b.resume).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "handle": handle, "resumed": b.resume })))
}

/// Migration IN (§5.6): the new custodian takes over, binding the handle to
/// the same key with provenance `rehomed:<old>`. The statement must name THIS
/// registrar as its destination, must be fresh and unspent, and the registrar
/// it claims to come from must independently agree it released the handle to
/// us — a self-signed statement alone is not custody.
async fn handles_rehome_in(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(b): Json<RehomeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let ip = client_ip(&headers, Some(peer)).unwrap_or_else(|| "unknown".into());
    if !rehome_rate_ok(&pool, &ip).await {
        return Err(too_many());
    }
    let Some(me) = self_url() else {
        log::error!("[pan] rehome-in refused: PAN_SELF_URL is not set, so this registrar cannot check that a statement names it");
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "ok": false, "error": "this registrar is not configured to accept migrations in" })),
        ));
    };
    let handle = registrar::rehome_in(
        &pool, &b.handle, &b.old_registrar, &b.agent_id, &b.timestamp, &b.new_registrar, &b.signature, &me,
        b.anchor.as_deref(),
    )
    .await
    .map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "handle": handle, "claimed_via": format!("rehomed:{}", b.old_registrar) })))
}

#[derive(Deserialize)]
struct CheckinBody {
    agent_id: String,
    ts: i64,
    signature: String,
    #[serde(flatten)]
    profile: registrar::AgentProfile,
}

/// Signed agent check-in (adapter start): refreshes "last connected from".
/// The response echoes what was recorded so callers can self-verify.
async fn agent_checkin(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CheckinBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let Some(ip) = client_ip(&headers, Some(peer)) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "ok": false, "error": "could not determine caller address" })),
        ));
    };
    registrar::checkin(&pool, &body.agent_id, body.ts, &body.signature, &ip, &body.profile)
        .await
        .map_err(reg_err)?;
    log::info!("[pan] check-in: {} from {ip}", body.agent_id);
    Ok(Json(serde_json::json!({ "ok": true, "recorded_ip": ip })))
}

/// The PAN card (§5.1): the endpoints are the address. Presence is optional
/// and only present when the registrar actually observes it.
fn build_card(
    h: &registrar::Handle,
    listing: Option<&crate::model::Listing>,
    operator_name: Option<&str>,
    agent_decl: Option<&registrar::SeenRow>,
    key_history: &[registrar::KeyChange],
) -> serde_json::Value {
    // The declared agent profile (kind/host/platform) is public by decision:
    // self-declared, User-Agent trust class. IP and timestamps from the same
    // row stay owner-only and are NOT read here.
    let agent = agent_decl.and_then(|(_, _, kind, host, platform, _, _)| {
        if kind.is_some() || host.is_some() || platform.is_some() {
            Some(serde_json::json!({
                "kind": kind, "host": host, "platform": platform,
                "declared": true,
            }))
        } else {
            None
        }
    });
    // The encryption key (SPEC 4.3 / PAN SPEC 5.1): public so a correspondent
    // can seal content to this agent before first contact. A capability the
    // card advertises, not an address; absent means cleartext only.
    let encryption_key = agent_decl.and_then(|(_, _, _, _, _, _, ek)| ek.clone());
    let mut endpoints: Vec<serde_json::Value> = Vec::new();
    if let Some(l) = listing {
        // A key-bearing agent: the key is the address (its mesh inbox).
        if matches!(l.source.as_str(), "agent" | "agentmesh") {
            // `mesh` is where, alongside who (§5.1). It is what lets a resolver
            // on one instance reach an agent served by another: SPEC.md §21
            // precondition 6 — a consumer MUST NOT assume a resolved agent
            // lives on the instance it happens to be connected to. Taken from
            // the agent's own manifest when it declared one, else this
            // registrar's default serving mesh.
            let mesh = l
                .manifest
                .get("mesh")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .or_else(|| std::env::var("PAN_DEFAULT_MESH").ok())
                .filter(|s| !s.trim().is_empty());
            endpoints.push(serde_json::json!({
                "protocol": "agentmesh",
                "agent_id": l.source_id,
                "node": l.manifest.get("node").and_then(|n| n.get("id")).cloned(),
                "mesh": mesh,
            }));
        } else if let Some(url) = l.manifest.get("endpoint").and_then(|v| v.as_str()) {
            endpoints.push(serde_json::json!({ "protocol": l.protocol, "url": url }));
        }
    }
    // Presence only where observed; PAN builds no presence subsystem.
    let presence = listing.and_then(|l| {
        l.presence.as_ref().map(|state| serde_json::json!({
            "state": state, "last_seen_at": l.last_seen_at,
        }))
    });
    // A signature with no validity window verifies forever: a card captured
    // while alice was bound to K1 replays at any resolver doing a first-sight
    // pin long after she re-paired to K2 (§5.3 makes resolvers pin, which is
    // what makes the replay stick). `issued_at`/`expires_at`/`registrar` are
    // INSIDE the signed bytes, so they cannot be edited off the document, and
    // the served Cache-Control matches — §5.1's "the registrar's stated TTL"
    // now exists.
    let now = chrono::Utc::now();
    serde_json::json!({
        "handle": h.handle,
        // The operator's chosen public label, set under the verified email
        // session (PAN v0.3). Anchored, logged, consistent across the owner's
        // handles — but NOT verified identity.
        "operator": operator_name.map(|n| serde_json::json!({ "name": n })),
        "agent": agent,
        "encryption_key": encryption_key,
        "binding": h.bind_method,
        // §4.4: every recorded change of the agent key behind this name,
        // oldest first, inside the signed bytes. An identity field: pinning
        // (§5.3) alarms a repeat resolver when a key changes, but a resolver
        // seeing the handle for the FIRST time after a rebind has no pin, and
        // this is what tells it the record behind the name is younger than
        // the name. Empty means the name has pointed at its current key for
        // the whole of its current claim.
        "key_history": key_history.iter().map(|c| serde_json::json!({
            "changed_at": c.changed_at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            "old_key": c.old_key,
            "new_key": c.new_key,
            "method": c.method,
            // SPEC.md §5.3: the owner said the replaced key leaked. A receiver
            // refuses messages signed by a revoked key; a machine move is false.
            "old_key_revoked": c.old_key_revoked,
        })).collect::<Vec<_>>(),
        // How the claim was witnessed: 'email' (registrar saw the inbox
        // directly) or 'delegated:<partner>' (a partner attested it). A
        // relying party who requires first-hand witnessing can check this.
        "claimed_via": h.claimed_via,
        "claimed_at": h.created_at,
        "reserved": listing.is_none(),
        "presence": presence,
        "endpoints": endpoints,
        // Which registrar's word this is, and for how long.
        "registrar": self_url(),
        "issued_at": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "expires_at": (now + chrono::Duration::seconds(registrar::card_validity_secs()))
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    })
}

#[derive(Deserialize)]
struct ResolveQuery {
    handle: Option<String>,
    /// Reverse resolution (PAN v0.3): look up by agent key instead. The key
    /// is public (it rides on every signed envelope), so this exposes nothing
    /// a forward resolve would not.
    agent_id: Option<String>,
}

/// A resolve response, with the TTL §5.1 says consumers must honor.
type ResolveResponse = ([(axum::http::HeaderName, String); 1], Json<serde_json::Value>);

fn with_ttl(body: serde_json::Value) -> ResolveResponse {
    (
        [(
            axum::http::header::CACHE_CONTROL,
            format!("public, max-age={}", registrar::attachment_ttl_secs()),
        )],
        Json(body),
    )
}

/// Public exact-string resolution: handle -> card (PAN §5), or agent_id ->
/// card (reverse). The bound listing rides along for this registrar's own UI.
async fn resolve_handle(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<ResolveQuery>,
) -> Result<ResolveResponse, (StatusCode, Json<serde_json::Value>)> {
    // Every card and every referral this registrar serves is signed (§7.6), so
    // a registrar that cannot sign says so instead of emitting bytes that every
    // conforming resolver must discard (§5.3).
    if card_key().is_none() {
        return Err(cannot_sign());
    }
    let ip = client_ip(&headers, Some(peer)).unwrap_or_else(|| "unknown".into());
    let found = match (&q.handle, &q.agent_id) {
        (Some(h), _) => registrar::resolve(&pool, h).await.map_err(reg_err)?,
        (None, Some(a)) => {
            // Reverse resolution converts an agent key — which rides on every
            // signed envelope, so anyone who has received one message has one —
            // into a handle, and a handle contains the operator's real email
            // address. §5.4 gates the forward direction (email -> handles)
            // behind opt-in consent; this direction has no consent gate at all,
            // so at minimum it must not be farmable.
            // Set well above real use and below farming, per caller address.
            // The platform's own services reverse-resolve from one egress
            // address (the naming rule's doors on every registration and
            // renewal, the rooms service checking a creator's anchor), so the
            // addresses in PAN_REVERSE_TRUSTED_IPS get their own, higher
            // ceiling rather than raising it for everyone (plan item 14).
            let limit = registrar::reverse_limit_for(&ip);
            if !registrar::rate_ok(&pool, &format!("reverse:{ip}"), limit, 3600).await.map_err(reg_err)? {
                return Err(too_many_of("reverse resolutions"));
            }
            let found = registrar::resolve_by_agent(&pool, a).await.map_err(reg_err)?;
            // Optional stricter posture: apply §5.4's consent flag to the
            // reverse direction too. Off by default because the operator
            // console and the rooms service both turn observed keys into
            // handles for display, and every existing anchor has the flag off.
            match found {
                Some(h)
                    if std::env::var("PAN_REVERSE_REQUIRE_DISCOVERABLE").is_ok()
                        && !registrar::operator_discoverable_get(&pool, &h.email).await.map_err(reg_err)? =>
                {
                    None
                }
                other => other,
            }
        }
        (None, None) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "ok": false, "error": "pass handle= or agent_id=" })),
            ))
        }
    };
    // §5.6: a re-homed handle resolves to a REFERRAL, not a card — the name now
    // lives at another registrar of record. Consumers follow the referral
    // there; pins are unaffected (the key never moved). The lookup is separate
    // from `resolve` so the obligation outlives a later release of the row.
    let referral_for = |h: &registrar::Handle| h.rehomed_to.clone().map(|to| (h.handle.clone(), to, h.email.clone()));
    let rehomed = match &found {
        Some(h) => referral_for(h),
        None => match &q.handle {
            Some(h) => registrar::resolve_rehomed(&pool, h).await.map_err(reg_err)?,
            None => None,
        },
    };
    if let Some((handle, destination, anchor)) = rehomed {
        let operator = registrar::operator_get(&pool, &anchor).await.map_err(reg_err)?;
        let referral = registrar::build_referral(
            &handle,
            &destination,
            self_url().as_deref(),
            operator.as_deref(),
        );
        let Some((key, kid, sig)) = sign_doc(&referral) else { return Err(cannot_sign()) };
        return Ok(with_ttl(serde_json::json!({
            "ok": true,
            "referral": referral,
            "registrar_key": key,
            "registrar_kid": kid,
            "registrar_sig": sig,
        })));
    }
    // §5.8: a renamed handle past its window does not resolve, whether or not
    // its owner has released it yet; one released after a rename answers
    // "moved to" for the cooling-off period. Both are 404s: the name does not
    // resolve (§5), and the answer says where the agent went instead of
    // "no agent by that name".
    let now = chrono::Utc::now();
    let found = match found {
        Some(h) if registrar::rename_window_closed(&h, now) => None,
        other => other,
    };
    if found.is_none() {
        if let Some(asked) = &q.handle {
            if let Some((old, to, stopped)) = registrar::resolve_moved(&pool, asked).await.map_err(reg_err)? {
                return Err((
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "ok": false,
                        "error": registrar::moved_words(&old, &to, stopped),
                        "moved_to": to,
                        "stopped_at": stopped.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    })),
                ));
            }
        }
    }
    match found {
        None => Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "no agent by that name" })),
        )),
        Some(h) => {
            let notice = registrar::rename_notice(&h, now);
            let listing = match h.listing_id {
                Some(id) => store::get(&pool, id).await.map_err(|e| reg_err(e.into()))?,
                None => None,
            };
            let operator = registrar::operator_get(&pool, &h.email).await.map_err(reg_err)?;
            let decl = match h.listing_id {
                Some(id) => registrar::last_seen_ips(&pool, &[id])
                    .await
                    .map_err(reg_err)?
                    .remove(&id),
                None => None,
            };
            let key_history = registrar::key_history(&pool, &h.handle).await.map_err(reg_err)?;
            let card =
                build_card(&h, listing.as_ref(), operator.as_deref(), decl.as_ref(), &key_history);
            // Signed cards (PAN §5.3): Ed25519 over the canonical card, so
            // caches and relays cannot tamper.
            let Some((key, kid, sig)) = sign_doc(&card) else { return Err(cannot_sign()) };
            let mut body = serde_json::json!({
                "ok": true,
                "card": card,
                "listing": listing,
                "registrar_key": key,
                "registrar_kid": kid,
                "registrar_sig": sig,
            });
            // §5.8: the old name of a renamed agent resolves, with a notice
            // saying where it went and when this name stops. Outside the signed
            // card, which describes the agent, not the name's future.
            if let Some(n) = notice {
                body["notice"] = serde_json::to_value(&n).unwrap_or(serde_json::Value::Null);
            }
            Ok(with_ttl(body))
        }
    }
}

#[derive(Deserialize)]
struct RenameWindowBody {
    handle: String,
    to: String,
    days: Option<i64>,
}

/// POST /api/handles/rename-window (§5.8): the anchor, over its delegated
/// session, says its agent was renamed from `handle` (its own) to `to` (bound
/// to the same agent), and the old name keeps resolving with a notice
/// for `days` (default 30, at most 90). Releasing the old name is a separate
/// call (release-delegated), which ends the window early.
async fn handles_rename_window(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<RenameWindowBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let (email, provenance) = session_info_from(&pool, &headers).await?;
    if provenance.strip_prefix("delegated:").is_none() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "this route requires a delegated session" })),
        ));
    }
    if !registrar::handle_anchors_to(&body.handle, &email) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "ok": false, "error": "the old handle must be anchored to the email this session speaks for" })),
        ));
    }
    let days = body.days.unwrap_or(registrar::RENAME_WINDOW_DEFAULT_DAYS);
    let until = registrar::set_rename_window(&pool, &email, &body.handle, &body.to, days, &provenance)
        .await
        .map_err(reg_err)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "handle": body.handle.trim().to_lowercase(),
        "renamed_to": body.to.trim().to_lowercase(),
        "until": until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })))
}

/// GET /api/registrar-key — the key(s) cards are signed with, for verifiers
/// that want an out-of-band copy rather than trusting the resolve response.
///
/// §5.3 requires resolvers to PIN this key, which makes rotation a flag day
/// unless the registrar can say "these two keys are both mine" for the overlap.
/// So it publishes a SET with key ids: the current key first (and `keys` stays
/// the plain array of strings older verifiers already read, current key first),
/// plus any retired keys still worth honoring. Rotation is then additive —
/// publish the new key alongside the old, switch signing, drop the old later —
/// instead of every pinned resolver alarming at once.
async fn registrar_key() -> Json<serde_json::Value> {
    let Some(key) = card_key() else {
        return Json(serde_json::json!({
            "ok": false,
            "keys": [],
            "key_set": [],
            "error": "this registrar has no signing key configured"
        }));
    };
    let mut keys: Vec<String> = vec![key.public.clone()];
    let mut set: Vec<serde_json::Value> = vec![serde_json::json!({
        "kid": key.kid, "key": key.public, "status": "current", "use": "pan-card-signing",
    })];
    for (kid, public) in &key.retired {
        keys.push(public.clone());
        set.push(serde_json::json!({
            "kid": kid, "key": public, "status": "retired", "use": "pan-card-signing",
        }));
    }
    Json(serde_json::json!({
        "ok": true,
        "registrar": self_url(),
        "keys": keys,
        "key_set": set,
    }))
}

#[derive(Deserialize)]
struct OperatorBody {
    name: Option<String>,
    discoverable: Option<bool>,
}

/// Set/update the operator record: display name and/or the §5.4
/// discoverability consent (session-scoped, logged).
async fn operator_set(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Json(body): Json<OperatorBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let email = session_from(&pool, &headers).await?;
    let name = match body.name.as_deref() {
        Some(n) => Some(registrar::operator_set(&pool, &email, n).await.map_err(reg_err)?),
        None => registrar::operator_get(&pool, &email).await.map_err(reg_err)?,
    };
    if let Some(d) = body.discoverable {
        registrar::operator_discoverable_set(&pool, &email, d).await.map_err(reg_err)?;
    }
    let discoverable = registrar::operator_discoverable_get(&pool, &email).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "name": name, "discoverable": discoverable })))
}

/// Read the caller's own operator record (for UI prefill).
async fn operator_get(
    State(pool): State<PgPool>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let email = session_from(&pool, &headers).await?;
    let name = registrar::operator_get(&pool, &email).await.map_err(reg_err)?;
    let discoverable = registrar::operator_discoverable_get(&pool, &email).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "name": name, "discoverable": discoverable })))
}

#[derive(Deserialize)]
struct InviteBody {
    email: String,
}

/// POST /api/invite — a verified sender (PAN session) asks the mesh to invite
/// someone by email. Tied to the sender's proven email so it can't be an open
/// spam relay; it only notifies, it does not create any relationship.
async fn invite(
    State(pool): State<PgPool>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<InviteBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    // Not part of SPEC-NAMING: an operator's growth feature, off unless turned on.
    if !crate::config::invite_enabled() {
        return Err(not_configured("invitations"));
    }
    let from_email = session_from(&pool, &headers).await?;
    let from = registrar::operator_get(&pool, &from_email).await.map_err(reg_err)?
        .unwrap_or_else(|| from_email.clone());
    let target = body.email.trim().to_lowercase();
    if !target.contains('@') || target.len() < 3 {
        return Err((StatusCode::BAD_REQUEST, Json(serde_json::json!({ "ok": false, "error": "a valid email is required" }))));
    }
    // A session costs one throwaway mailbox, and there was no invite ceiling at
    // all: one verified anchor could address the whole world from this
    // registrar's sending domain. Per anchor and per caller address.
    let per_anchor = registrar::limit_from_env("PAN_INVITES_MAX_PER_DAY", 25);
    let per_ip = registrar::limit_from_env("PAN_INVITES_MAX_PER_IP_DAY", 50);
    let ip = client_ip(&headers, Some(peer)).unwrap_or_else(|| "unknown".into());
    if !registrar::rate_ok(&pool, &format!("invite:anchor:{from_email}"), per_anchor, 86_400).await.map_err(reg_err)?
        || !registrar::rate_ok(&pool, &format!("invite:ip:{ip}"), per_ip, 86_400).await.map_err(reg_err)?
    {
        return Err(too_many_of("invitations"));
    }
    let delivery = send_invite(&target, &from).await;
    Ok(Json(serde_json::json!({ "ok": true, "delivery": delivery })))
}

/// Send an invite email (best-effort), from the registrar's own name.
async fn send_invite(to: &str, from_name: &str) -> &'static str {
    let name = crate::config::registrar_name();
    let get = crate::config::get_a_name_url();
    let text = format!(
        "{from_name} wants their AI agent to be able to reach yours.

         A Personal Agent Naming handle gives your agent a name others can reach it by,          and lets you decide who gets through. Get one at {get}

         If this doesn't mean anything to you, you can ignore it.

{}",
        crate::mail::footer_text()
    );
    crate::mail::send(
        crate::mail::Message {
            to,
            // Fixed subject line. The display name is 80 characters of whatever its
            // owner typed, and putting it in the subject made this endpoint a way to
            // write the subject line of mail from this registrar's domain. It still
            // appears in the body, where it is the sender's own claimed label and
            // reads as one.
            subject: format!("Someone wants to connect, through {name}"),
            text,
            html: None,
        },
        "invite",
        false,
    )
    .await
}

/// GET /a/:handle — a shareable, human-readable card page for a handle. The
/// artifact you drop in a text: it shows who the agent is (verified), and
/// gives someone with no agent a way to get one.
async fn card_page(
    State(pool): State<PgPool>,
    Path(handle): Path<String>,
) -> axum::response::Html<String> {
    // esc() is the module-level helper.
    let found = registrar::resolve(&pool, &handle).await.ok().flatten();
    let inner = match found {
        None => format!(
            "<h1>Not found</h1><p class=\"dim\">No agent resolves to <span class=\"mono\">{}</span>.</p>",
            esc(&handle)
        ),
        Some(h) => {
            let operator = registrar::operator_get(&pool, &h.email).await.ok().flatten();
            let bound = h.listing_id.is_some();
            let status = if bound { "<span class=\"badge ok\">verified handle</span>" } else { "<span class=\"badge\">reserved</span>" };
            // §4.4: a key change is stated in plain words, with its date, so a
            // person checking a name they were given does not need to read
            // JSON to learn that the record behind the name is younger than
            // the name.
            let history = registrar::key_history(&pool, &h.handle).await.unwrap_or_default();
            let keymove = history.last().map(|last| {
                let date = last.changed_at.format("%B %-d, %Y");
                let sentence = if last.new_key.is_some() && last.old_key_revoked {
                    format!(
                        "This name moved to a new key on {date} because its owner reported the \
                         previous key leaked. That key is revoked: a message signed by it is not \
                         from this agent."
                    )
                } else if last.new_key.is_some() {
                    format!(
                        "This name moved to a new key on {date}. History before that date belongs \
                         to the previous key, not to the agent answering now."
                    )
                } else {
                    format!(
                        "This name was detached from its previous key on {date}. History before \
                         that date belongs to that key, not to this name."
                    )
                };
                let count = if history.len() > 1 {
                    format!(
                        " The key behind this name has changed {} times in its current claim.",
                        history.len()
                    )
                } else {
                    String::new()
                };
                format!("<p class=\"keymove\">{sentence}{count}</p>")
            })
            .unwrap_or_default();
            format!(
                "<div class=\"card\">\
                   <div class=\"lamp\"></div>\
                   <h1 class=\"mono\">{handle}</h1>\
                   {op}\
                   <div class=\"row\">{status}</div>\
                   <p class=\"dim\">{reach}</p>\
                   {keymove}\
                 </div>",
                handle = esc(&h.handle),
                op = operator.map(|o| format!("<p class=\"op\">operated by {}</p>", esc(&o))).unwrap_or_default(),
                status = status,
                reach = if bound {
                    "This is an AI agent with a Personal Agent Naming handle. If you have an agent too, it can reach this one by name."
                } else {
                    "This name is claimed but not yet connected to an agent."
                },
                keymove = keymove,
            )
        }
    };
    axum::response::Html(format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <link rel=\"icon\" href=\"/favicon.svg\">\
         <title>{title} · {brand}</title><style>\
         body{{background:#0A1417;color:#E7EFEC;font-family:system-ui,sans-serif;line-height:1.6;\
           display:flex;min-height:100vh;margin:0;align-items:center;justify-content:center;padding:24px}}\
         .wrap{{max-width:460px;width:100%;text-align:center}}\
         .card{{background:#0F1D22;border:1px solid #1C2E33;border-radius:16px;padding:36px 28px;margin-bottom:22px}}\
         .lamp{{width:12px;height:12px;border-radius:50%;background:#43D6A6;margin:0 auto 18px;box-shadow:0 0 0 4px rgba(67,214,166,.15)}}\
         h1{{font-size:1.15rem;word-break:break-all;margin:0 0 6px}}\
         .op{{color:#7C918C;margin:0 0 16px;font-size:.9rem}}\
         .mono{{font-family:ui-monospace,monospace}}.dim{{color:#7C918C;font-size:.92rem}}\
         .row{{margin:14px 0}}\
         .badge{{font-family:ui-monospace,monospace;font-size:.72rem;padding:3px 10px;border-radius:999px;border:1px solid #1C2E33;color:#7C918C}}\
         .badge.ok{{color:#43D6A6;border-color:rgba(67,214,166,.3)}}\
         .keymove{{color:#F2A93B;font-size:.88rem;text-align:left;border:1px solid rgba(242,169,59,.35);\
           border-radius:9px;padding:10px 14px;margin:16px 0 0;background:rgba(242,169,59,.06)}}\
         a.cta{{display:inline-block;background:#F2A93B;color:#20140a;font-weight:600;text-decoration:none;\
           padding:12px 22px;border-radius:9px;font-size:.95rem}}\
         .foot{{color:#4A5D5A;font-size:.8rem;margin-top:16px}}\
         </style></head><body><div class=\"wrap\">{inner}\
         <a class=\"cta\" href=\"{get}\">Get a name for your agent</a>\
         <p class=\"foot\">{brand}: a Personal Agent Naming registrar</p></div></body></html>",
        title = esc(&handle), inner = inner,
        get = esc(&crate::config::get_a_name_url()),
        brand = esc(&crate::config::registrar_name()),
    ))
}

#[derive(Deserialize)]
struct DiscoverQuery {
    email: String,
}

/// GET /api/discover?email=… — §5.4 discovery, the consented exception to
/// no-enumeration. Public. Not-opted-in and no-such-anchor answer
/// identically (discoverable: false), by design.
async fn discover(
    State(pool): State<PgPool>,
    Query(q): Query<DiscoverQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    match registrar::discover_by_email(&pool, &q.email).await.map_err(reg_err)? {
        None => Ok(Json(serde_json::json!({ "ok": true, "discoverable": false, "handles": [] }))),
        Some(handles) => {
            let operator = registrar::operator_get(&pool, &q.email.trim().to_lowercase()).await.map_err(reg_err)?;
            let rows: Vec<serde_json::Value> = handles.iter().map(|h| serde_json::json!({
                "handle": h.handle,
                "bound": h.listing_id.is_some(),
            })).collect();
            Ok(Json(serde_json::json!({ "ok": true, "discoverable": true, "operator": operator, "handles": rows })))
        }
    }
}

#[derive(Deserialize)]
struct WebFingerQuery {
    resource: String,
}

/// WebFinger (RFC 7033, PAN §5.2): a handle is a valid acct: URI.
#[derive(serde::Deserialize)]
struct CommitmentsQuery {
    since: Option<i64>,
    limit: Option<i64>,
}

/// GET /api/log-commitments — the registrar's signed statements about where its
/// history chain ends (§6).
///
/// PUBLIC, and it has to be. A commitment is only worth anything to somebody who
/// kept an earlier one, so the point of the endpoint is that third parties can
/// archive them without asking permission. It discloses no history: a
/// commitment is a hash, a count and a sequence number, and none of those names
/// a handle or an owner — which is what lets this coexist with the
/// crypto-shredding in migration 0013.
///
/// `canonical` is served alongside so a verifier can rebuild the signed bytes
/// from the published fields without reading this source. Verify against the
/// key with the matching `kid` from `/api/registrar-key`, which keeps publishing
/// retired keys so old commitments stay checkable across a rotation.
async fn log_commitments(
    State(pool): State<PgPool>,
    Query(q): Query<CommitmentsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let rows = registrar::list_log_commitments(&pool, q.since.unwrap_or(0), q.limit.unwrap_or(100))
        .await
        .map_err(reg_err)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "registrar": self_url(),
        "canonical": "pan-log-commitment-v1\\n<registrar>\\n<head_seq>\\n<entries>\\n<head_hash>\\n<issued_at>",
        "verify": "ed25519 over the canonical bytes, base64 signature, key = the /api/registrar-key entry whose kid matches",
        "note": "a chain that later reports fewer entries than a commitment you already hold contradicts a signature this registrar cannot disown",
        "commitments": rows,
    })))
}

async fn webfinger(
    State(pool): State<PgPool>,
    Query(q): Query<WebFingerQuery>,
) -> Result<([(axum::http::HeaderName, &'static str); 1], Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let handle = q.resource.strip_prefix("acct:").unwrap_or(&q.resource);
    let found = registrar::resolve(&pool, handle).await.map_err(reg_err)?;
    let Some(h) = found else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "ok": false, "error": "no agent by that name" })),
        ));
    };
    // A handle that re-homed still answers WebFinger, but it points at the card
    // where the card now lives (§5.6) rather than at this registrar, which no
    // longer has one to serve.
    //
    // ABSOLUTE, both ways. RFC 7033 links carry a URI, and the local branch used
    // to emit a bare path — which resolves only for a client that kept the base
    // it fetched from, and not at all for one that copied the link out of the
    // JRD. The re-homed branch was already absolute because it had to be, so the
    // two branches disagreed about what an href is. `PAN_SELF_URL` is the same
    // value migration IN checks statements against, so if it is wrong this is
    // not the first thing to break; unset, the old relative form is still served
    // rather than inventing a hostname from the request.
    let path = format!("/api/resolve?handle={}", urlencode(&h.handle));
    let card_href = match (&h.rehomed_to, self_url()) {
        (Some(to), _) => format!("{}{path}", to.trim_end_matches('/')),
        (None, Some(me)) => format!("{}{path}", me.trim_end_matches('/')),
        (None, None) => path,
    };
    let jrd = serde_json::json!({
        "subject": format!("acct:{}", h.handle),
        "properties": {
            "urn:pan:binding": h.bind_method,
        },
        "links": [{
            "rel": "urn:pan:card",
            "type": "application/json",
            "href": card_href,
        }],
    });
    Ok(([(axum::http::header::CONTENT_TYPE, "application/jrd+json")], Json(jrd)))
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    limit: Option<i64>,
}

/// Owner-scoped: the caller's own handle history, behind the verified
/// session. The log is not world-readable (PAN §6).
async fn handles_log(
    State(pool): State<PgPool>,
    headers: HeaderMap,
    Query(q): Query<LogQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let email = session_from(&pool, &headers).await?;
    let entries =
        registrar::log_entries(&pool, &email, q.limit.unwrap_or(100)).await.map_err(reg_err)?;
    Ok(Json(serde_json::json!({ "ok": true, "entries": entries })))
}

// Which credential authorizes what, decided without a process environment or a
// socket. The HTTP half of this — the statuses these decisions turn into — is in
// `crate::http_tests`.
#[cfg(test)]
mod credentials {
    use super::*;

    #[test]
    fn the_operator_secret_wins_and_the_witness_secret_is_the_fallback() {
        // §9 as asked for: two values, two authorities.
        assert_eq!(
            moderation_secret_from(Some("moderate"), Some("witness")),
            (SecretSplit::Separate, Some("moderate".to_string()))
        );
        // The deployment this change had to not break: only the old secret set,
        // moderation still works, and the split is reported as not done.
        assert_eq!(
            moderation_secret_from(None, Some("witness")),
            (SecretSplit::FellBackToWitness, Some("witness".to_string()))
        );
        // Neither: both authorities off (the routes answer 501).
        assert_eq!(moderation_secret_from(None, None), (SecretSplit::Unconfigured, None));
        // A moderation secret with no witnessing secret is a legitimate
        // deployment — one that moderates but accepts no delegated sessions.
        assert_eq!(
            moderation_secret_from(Some("moderate"), None),
            (SecretSplit::Separate, Some("moderate".to_string()))
        );
    }

    #[test]
    fn two_settings_holding_one_value_are_not_two_credentials() {
        // THE CASE THAT LOOKS SPLIT AND IS NOT. It still authorizes — refusing
        // would be an outage over a configuration no less safe than the fallback
        // — but it is reported as its own state so startup can say so at error
        // level rather than congratulating the operator.
        assert_eq!(
            moderation_secret_from(Some("same"), Some("same")),
            (SecretSplit::SetIdentically, Some("same".to_string()))
        );
        // One trailing byte apart IS apart. Nothing here trims, because the
        // expected value is compared byte-for-byte with what a caller sends and
        // trimming one side would break a caller whose secret store appended a
        // newline.
        assert_eq!(
            moderation_secret_from(Some("same\n"), Some("same")).0,
            SecretSplit::Separate
        );
    }

    #[test]
    fn secret_comparison_is_exact() {
        assert!(secret_matches("s3cret", "s3cret"));
        assert!(!secret_matches("", "s3cret"));
        assert!(!secret_matches("s3cret", ""));
        // A prefix must not pass: the fold-based comparison exists so a wrong
        // secret leaks no timing signal, not so it can be lenient.
        assert!(!secret_matches("s3cre", "s3cret"));
        assert!(!secret_matches("s3crett", "s3cret"));
        assert!(!secret_matches("S3CRET", "s3cret"));
        assert!(secret_matches("", ""));
    }
}

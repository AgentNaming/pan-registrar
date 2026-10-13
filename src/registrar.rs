//! The registrar: email-anchored handle claims.
//!
//! A handle is one globally unique string, `<name>.<email>`. Nobody parses
//! it — resolution is exact-string lookup, uniqueness is enforced on the
//! full string at claim time (first come, first served). The email is the
//! anchor: proving control of it (a 6-digit code) is what authorizes claims
//! under it. Every registrar action appends to the handle_log, which is NOT
//! public (SPEC-NAMING §6): it is owner-scoped, served only to the anchor
//! owner behind a verified session, because handles embed the owner's address
//! and a world-readable log would let anyone enumerate an owner's whole
//! roster by filtering on their email.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::PgPool;
use uuid::Uuid;

/// How long a released handle stays unclaimable — a business card in a
/// drawer shouldn't silently start pointing at a stranger.
const COOLING_OFF_DAYS: i64 = 90;
const CODE_TTL_MIN: i64 = 15;
const SESSION_TTL_MIN: i64 = 480; // 8h console sessions (user call 2026-07-18)
const MAX_CODES_PER_HOUR: i64 = 5;
const MAX_CODE_ATTEMPTS: i32 = 5;

/// How long the anchor owner has to reverse a re-home they did not authorize
/// (§5.6 moves are key-signed, so the mailbox owner is not a party to them).
/// The undo is the owner standing the move itself does not carry: see
/// `rehome_undo`.
const REHOME_UNDO_DAYS: i64 = 30;

/// After an undo, re-homing that handle is paused for this long, so the same
/// key cannot simply sign a fresh statement and move the name straight back
/// out. The owner can lift the hold under a verified session.
const REHOME_HOLD_DAYS: i64 = 30;

/// How long a peer registrar's published signing keys are cached in process.
const PEER_KEY_TTL_SECS: u64 = 600;

/// How long a signed card (and a signed referral) stays valid. A signature
/// with no expiry verifies forever, which is what let a captured card be
/// replayed at a resolver doing a first-sight pin (§5.3).
pub fn card_validity_secs() -> i64 {
    card_ttl_secs()
}

fn card_ttl_secs() -> i64 {
    std::env::var("PAN_CARD_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v >= 60 && *v <= 86_400)
        .unwrap_or(3600)
}

/// Attachment data (endpoints, presence) is expected to move, so it gets a TTL
/// an order of magnitude shorter than the identity fields it travels with
/// (§5.1). This is the number served as `Cache-Control: max-age`.
pub fn attachment_ttl_secs() -> i64 {
    (card_ttl_secs() / 10).max(30)
}

/// Constant-time byte comparison. Used wherever a caller-supplied secret is
/// compared to a stored one, so a wrong value leaks no length/timing signal.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Debug)]
pub enum RegistrarError {
    Invalid(String),
    Taken(String),
    /// A ceiling was hit, not a bad request: the caller should back off rather
    /// than change what it asked for (HTTP 429).
    TooMany(String),
    Unauthorized,
    /// The session is valid and the caller is who they say they are; what they
    /// asked for is outside what this session may do (HTTP 403). Distinct from
    /// `Unauthorized` on purpose: telling a caller with a live session to "verify
    /// your email again" sends them to re-authenticate against a refusal that
    /// re-authenticating cannot lift.
    Forbidden(String),
    Db(sqlx::Error),
}

impl std::fmt::Display for RegistrarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistrarError::Invalid(m) => write!(f, "{m}"),
            RegistrarError::Taken(m) => write!(f, "{m}"),
            RegistrarError::TooMany(m) => write!(f, "{m}"),
            RegistrarError::Unauthorized => write!(f, "not authorized"),
            RegistrarError::Forbidden(m) => write!(f, "{m}"),
            RegistrarError::Db(e) => write!(f, "storage error: {e}"),
        }
    }
}
impl From<sqlx::Error> for RegistrarError {
    fn from(e: sqlx::Error) -> Self {
        RegistrarError::Db(e)
    }
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct Handle {
    pub handle: String,
    pub email: String,
    pub listing_id: Option<Uuid>,
    pub anchor: String,
    pub bind_method: Option<String>,
    pub verified_at: Option<DateTime<Utc>>,
    pub stale: bool,
    pub created_at: DateTime<Utc>,
    pub released_at: Option<DateTime<Utc>>,
    /// How the claim was witnessed: 'email' (direct verification) or
    /// 'delegated:<partner>' (a trusted partner attested it). On the card.
    pub claimed_via: String,
    /// Set when the handle has re-homed to another registrar (§5.6): the new
    /// registrar's URL. Resolution then returns a referral, not a card, and the
    /// name cannot be re-issued here. NULL for a handle that lives here.
    pub rehomed_to: Option<String>,
    /// When the move happened. The anchor owner has REHOME_UNDO_DAYS from here
    /// to reverse it, so the owner-facing roster can show the deadline rather
    /// than leaving them to discover the window by missing it.
    pub rehomed_at: Option<DateTime<Utc>>,
    /// Set when the agent was renamed within this registrar (§5.8): the new
    /// handle. Until `renamed_until` this handle still resolves, with a notice;
    /// after it, or once released, it answers "moved to" the new handle.
    pub renamed_to: Option<String>,
    pub renamed_at: Option<DateTime<Utc>>,
    pub renamed_until: Option<DateTime<Utc>>,
}

macro_rules! handle_cols {
    () => {
        "handle, email, listing_id, anchor, bind_method, verified_at, stale, created_at, released_at, claimed_via, rehomed_to, rehomed_at, renamed_to, renamed_at, renamed_until"
    };
}

fn normalize_email(email: &str) -> Result<String, RegistrarError> {
    let e = email.trim().to_lowercase();
    let parts: Vec<&str> = e.split('@').collect();
    if parts.len() != 2
        || parts[0].is_empty()
        || !parts[1].contains('.')
        || e.contains(char::is_whitespace)
        || e.len() > 254
    {
        return Err(RegistrarError::Invalid("that doesn't look like an email address".into()));
    }
    Ok(e)
}

fn validate_name(name: &str) -> Result<String, RegistrarError> {
    let n = name.trim().to_string();
    if n.is_empty() || n.len() > 64 {
        return Err(RegistrarError::Invalid("name must be 1–64 characters".into()));
    }
    if n.contains(char::is_whitespace) || n.contains('@') || n.chars().any(char::is_control) {
        return Err(RegistrarError::Invalid("name can't contain spaces or '@'".into()));
    }
    Ok(n)
}

/// Count-and-claim one slot in a named bucket, in the database rather than in
/// process memory. Cloud Run runs several instances of this service, so an
/// in-process limiter's real ceiling is the configured one multiplied by the
/// instance count — which is no ceiling at all for anything that matters.
/// Returns false when the bucket is already at its limit for the window.
///
/// The count and the insert are one statement, so two concurrent callers
/// cannot both see "one slot left".
pub async fn rate_ok(
    pool: &PgPool,
    bucket: &str,
    limit: i64,
    window_secs: i64,
) -> Result<bool, RegistrarError> {
    if limit <= 0 {
        return Ok(false);
    }
    let claimed: Option<(i32,)> = sqlx::query_as(
        "WITH recent AS ( \
             SELECT count(*) AS c FROM rate_events \
             WHERE bucket = $1 AND at > now() - ($2 || ' seconds')::interval \
         ) \
         INSERT INTO rate_events (bucket) SELECT $1 FROM recent WHERE recent.c < $3 RETURNING 1",
    )
    .bind(bucket)
    .bind(window_secs.to_string())
    .bind(limit)
    .fetch_optional(pool)
    .await?;
    // Old rows are dead weight; prune occasionally rather than on a timer.
    if Uuid::new_v4().as_bytes()[0] < 4 {
        let _ = sqlx::query("DELETE FROM rate_events WHERE at < now() - interval '2 days'")
            .execute(pool)
            .await;
    }
    Ok(claimed.is_some())
}

/// An env-configured ceiling, with a default. Ops needs to be able to open
/// these up for a test rig and tighten them under abuse without a rebuild.
pub fn limit_from_env(var: &str, default: i64) -> i64 {
    std::env::var(var).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Default reverse lookups per hour for any one caller address.
pub const REVERSE_MAX_PER_HOUR: i64 = 300;
/// Default for a caller address named in `PAN_REVERSE_TRUSTED_IPS`.
pub const REVERSE_TRUSTED_MAX_PER_HOUR: i64 = 20_000;

/// Whether `ip` is one of the listed addresses. The list is the platform's own
/// hosts (docs/no-anonymous-agents-plan.md item 14): every platform service
/// reverse-resolves from one egress address, and the naming rule's doors ask
/// on every registration and credential renewal, so the ceiling meant to stop
/// a stranger farming handles would otherwise throttle the mesh itself.
/// Commas or whitespace separate entries; both sides are parsed as addresses,
/// so two spellings of one address match and an unparsable entry matches
/// nothing. "unknown" (no address could be read) is never trusted.
pub fn reverse_caller_trusted(ip: &str, list: Option<&str>) -> bool {
    let Ok(ip) = ip.trim().parse::<std::net::IpAddr>() else { return false };
    list.unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
        .any(|t| t == ip)
}

/// The reverse-lookup ceiling for one caller address: `base` for everyone,
/// `trusted` (never lower than `base`) for a listed platform address. Pure,
/// so the rule is testable without the environment.
pub fn reverse_limit(ip: &str, base: i64, trusted_list: Option<&str>, trusted: i64) -> i64 {
    if reverse_caller_trusted(ip, trusted_list) { trusted.max(base) } else { base }
}

/// The same, read from the environment: PAN_REVERSE_MAX_PER_HOUR for everyone,
/// PAN_REVERSE_TRUSTED_MAX_PER_HOUR for the addresses in PAN_REVERSE_TRUSTED_IPS.
pub fn reverse_limit_for(ip: &str) -> i64 {
    reverse_limit(
        ip,
        limit_from_env("PAN_REVERSE_MAX_PER_HOUR", REVERSE_MAX_PER_HOUR),
        std::env::var("PAN_REVERSE_TRUSTED_IPS").ok().as_deref(),
        limit_from_env("PAN_REVERSE_TRUSTED_MAX_PER_HOUR", REVERSE_TRUSTED_MAX_PER_HOUR),
    )
}

#[cfg(test)]
mod reverse_limit_tests {
    use super::*;

    #[test]
    fn a_stranger_gets_the_ordinary_ceiling() {
        assert_eq!(reverse_limit("203.0.113.9", 300, Some("198.51.100.71"), 20_000), 300);
        assert_eq!(reverse_limit("203.0.113.9", 300, None, 20_000), 300);
    }

    #[test]
    fn a_listed_platform_address_gets_the_higher_one() {
        let list = Some("198.51.100.71, 198.51.100.155");
        assert_eq!(reverse_limit("198.51.100.71", 300, list, 20_000), 20_000);
        assert_eq!(reverse_limit("198.51.100.155", 300, list, 20_000), 20_000);
        assert!(reverse_caller_trusted("198.51.100.155", Some("198.51.100.71 198.51.100.155")));
    }

    #[test]
    fn the_trusted_ceiling_never_lowers_the_ordinary_one() {
        assert_eq!(reverse_limit("198.51.100.71", 300, Some("198.51.100.71"), 10), 300);
    }

    #[test]
    fn spellings_of_one_address_match_and_junk_matches_nothing() {
        assert!(reverse_caller_trusted("2001:db8::1", Some("2001:0db8:0:0:0:0:0:1")));
        assert!(!reverse_caller_trusted("unknown", Some("unknown")));
        assert!(!reverse_caller_trusted("198.51.100.7", Some("198.51.100.71")));
        assert!(!reverse_caller_trusted("198.51.100.71", Some("")));
        assert!(!reverse_caller_trusted("198.51.100.71", Some("not-an-ip")));
    }
}

/// Bytes from the operating system's random source. A registrar that cannot
/// read it cannot mint a code anyone should trust, so it stops rather than
/// fall back to something weaker.
pub(crate) fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the operating system's random source is unavailable");
    b
}

/// Random 6-digit code. Drawn by rejection, so every code is equally likely:
/// the largest multiple of a million below 2^32 is the cut-off.
fn six_digit_code() -> String {
    const LIMIT: u32 = u32::MAX - (u32::MAX % 1_000_000);
    loop {
        let n = u32::from_le_bytes(random_bytes::<4>());
        if n < LIMIT {
            return format!("{:06}", n % 1_000_000);
        }
    }
}

/// Start verification: mint a code for this email. The caller delivers it
/// (email provider in production; server log in dev).
///
/// Three ceilings, not one (§9 "registrars MUST rate-limit code issuance per
/// anchor" is the floor, not the whole job): per anchor, per caller address,
/// and one for the whole service. The per-anchor limit bounds what one victim
/// receives; only the other two bound what the registrar's domain sends in
/// total, which is what a rotating recipient list turns into.
pub async fn start_verification(
    pool: &PgPool,
    email: &str,
    ip: &str,
) -> Result<(String, String), RegistrarError> {
    let email = normalize_email(email)?;
    if !rate_ok(pool, &format!("codes:ip:{ip}"), limit_from_env("PAN_CODES_MAX_PER_IP_HOUR", 15), 3600).await? {
        return Err(RegistrarError::TooMany(
            "too many verification codes requested from this address — try again later".into(),
        ));
    }
    if !rate_ok(pool, "codes:global", limit_from_env("PAN_CODES_MAX_PER_HOUR", 500), 3600).await? {
        return Err(RegistrarError::TooMany(
            "this registrar is sending more verification codes than it will in one hour — try again later".into(),
        ));
    }
    let (recent,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM email_codes WHERE email = $1 AND created_at > now() - interval '1 hour'",
    )
    .bind(&email)
    .fetch_one(pool)
    .await?;
    if recent >= MAX_CODES_PER_HOUR {
        return Err(RegistrarError::TooMany(
            "too many codes requested — try again in an hour".into(),
        ));
    }
    let code = six_digit_code();
    sqlx::query(
        "INSERT INTO email_codes (email, code, expires_at) VALUES ($1, $2, now() + ($3 || ' minutes')::interval)",
    )
    .bind(&email)
    .bind(&code)
    .bind(CODE_TTL_MIN.to_string())
    .execute(pool)
    .await?;
    Ok((email, code))
}

/// Trade a correct code for a short-lived session token.
pub async fn verify_code(pool: &PgPool, email: &str, code: &str) -> Result<Uuid, RegistrarError> {
    let email = normalize_email(email)?;
    let row: Option<(String, i32)> = sqlx::query_as(
        r#"
        UPDATE email_codes SET attempts = attempts + 1
        WHERE ctid = (
            SELECT ctid FROM email_codes
            WHERE email = $1 AND expires_at > now() AND attempts < $2
            ORDER BY created_at DESC LIMIT 1
        )
        RETURNING code, attempts
        "#,
    )
    .bind(&email)
    .bind(MAX_CODE_ATTEMPTS)
    .fetch_optional(pool)
    .await?;

    // Constant-time: six digits and five attempts make a timing oracle
    // impractical either way, but a code comparison is exactly the place not to
    // leave one.
    let ok = matches!(&row, Some((real, _)) if ct_eq(real.as_bytes(), code.trim().as_bytes()));
    if !ok {
        return Err(RegistrarError::Invalid("wrong or expired code".into()));
    }
    sqlx::query("DELETE FROM email_codes WHERE email = $1").bind(&email).execute(pool).await?;
    mint_session(pool, &email).await
}

/// Mint a directly-verified session (provenance 'email'): the tail of
/// `verify_code`, after the code checks out.
pub async fn mint_session(pool: &PgPool, email: &str) -> Result<Uuid, RegistrarError> {
    mint_session_as(pool, email, "email").await
}

/// Mint a session with explicit provenance. The second use is delegated
/// witnessing: a trusted partner service that has itself verified the email
/// (the mesh control plane, core §4.9 account session) obtains a PAN session
/// so it can claim/bind a name on the user's behalf, sparing them a second
/// email round trip. Provenance is recorded on the session, disclosed on
/// everything the session establishes, and a delegated session can establish
/// (claim, pair, bind) but never destroy (release) — the API layer enforces
/// that scope.
pub async fn mint_session_as(
    pool: &PgPool,
    email: &str,
    provenance: &str,
) -> Result<Uuid, RegistrarError> {
    let email = normalize_email(email)?;
    let (token,): (Uuid,) = sqlx::query_as(
        "INSERT INTO email_sessions (email, provenance, expires_at) \
         VALUES ($1, $2, now() + ($3 || ' minutes')::interval) RETURNING token",
    )
    .bind(&email)
    .bind(provenance)
    .bind(SESSION_TTL_MIN.to_string())
    .fetch_one(pool)
    .await?;
    // Expired sessions were never removed. Every lookup already filters on
    // `expires_at > now()`, so a stale row cannot authorize anything — but it is
    // a row naming a person, kept forever, in a table whose whole purpose ended
    // when it expired. Pruned probabilistically here rather than on a timer, the
    // same way `rate_events` is, so there is no scheduler to own.
    if Uuid::new_v4().as_bytes()[0] < 4 {
        let _ = sqlx::query("DELETE FROM email_sessions WHERE expires_at < now() - interval '1 day'")
            .execute(pool)
            .await;
    }
    Ok(token)
}

/// The email a live session belongs to.
pub async fn session_email(pool: &PgPool, token: Uuid) -> Result<String, RegistrarError> {
    session_info(pool, token).await.map(|(email, _)| email)
}

/// The email AND provenance of a live session ('email' or 'delegated:<partner>').
pub async fn session_info(pool: &PgPool, token: Uuid) -> Result<(String, String), RegistrarError> {
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT email, provenance FROM email_sessions WHERE token = $1 AND expires_at > now()",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    row.ok_or(RegistrarError::Unauthorized)
}

/// Canonical JSON for hashing and card signatures, per RFC 8785 (the JSON
/// Canonicalization Scheme, the same rule Agent Messaging signs under):
/// compact, object keys sorted by their UTF-16 code units, strings escaped
/// the minimal way, and numbers in their ECMAScript form. Explicit so neither
/// the log chain nor a card signature ever depends on serde_json's
/// map-ordering configuration.
///
/// Every key the registrar signs today is ASCII and every number an integer,
/// where UTF-16 order is byte order and serde_json prints exactly what
/// RFC 8785 asks, so the bytes of every card and log entry written before the
/// sort and the number form were made explicit are unchanged.
pub fn canonical_json(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let inner: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::Value::String(k.clone()), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        serde_json::Value::Number(n) if n.is_f64() => {
            // ECMAScript's Number-to-String, as RFC 8785 §3.2.2.3 requires: 1.0
            // is "1", 1e21 is "1e+21". JSON cannot carry NaN or infinities, so
            // every f64 here is finite.
            let f = n.as_f64().unwrap_or(0.0);
            ryu_js::Buffer::new().format_finite(f).to_string()
        }
        other => other.to_string(),
    }
}

/// Who a `handle_log` entry belongs to. There are two shapes, and which one a
/// row has decides which canonicalization rule its `entry_hash` was computed
/// under (see [`log_entry_canonical`]). The cutover between them is migration
/// 0013; `registrar_meta.log_email_cutover_seq` records the last id that
/// predates it.
// `Anchor` is only constructed when READING a pre-cutover row, which today
// happens in `log_entries` (through `LogRow`) and in the chain tests. The
// writer never produces it again, by design.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub enum LogOwner<'a> {
    /// PRE-CUTOVER (before migration 0013). The row carries the owner's email in
    /// plaintext and the whole handle, which for an email-tier handle spells the
    /// address out a second time. These rows are not rewritten and cannot be
    /// erased — see 0013 for why that is deliberate.
    Anchor { handle: &'a str, email: &'a str },
    /// POST-CUTOVER. The row carries an opaque token and the anchor-free name.
    /// `handle_name` is None for the anchor-level actions ('operator',
    /// 'discoverable') that concern no handle. Nothing here identifies a person
    /// once the matching `log_owner_tokens` row is gone.
    Token { handle_name: Option<&'a str>, owner_token: &'a str },
}

/// The exact bytes an entry's `entry_hash` covers.
///
/// ONE CHAIN, TWO RULES. `prev_hash` links every row to the one before it
/// regardless of shape, so the chain is unbroken across the 0013 cutover and a
/// verifier walks it end to end. What differs is only the per-entry
/// serialization: a pre-cutover row hashes `email` and `handle`, a post-cutover
/// row hashes `owner_token` and `handle_name`. A verifier picks the rule from
/// the row itself — `owner_token IS NULL` means rule one — and the two can never
/// be confused for each other, because the key names differ and no row is
/// allowed to carry both sets (the `handle_log_owner_shape` CHECK).
///
/// The token is inside the hash and the email is not, which is the whole point:
/// deleting the token-to-email mapping changes no hashed byte, so erasure cannot
/// break the chain and a broken chain can never be blamed on an erasure.
pub fn log_entry_canonical(
    seq: i64,
    at: &DateTime<Utc>,
    action: &str,
    detail: &serde_json::Value,
    prev_hash: &str,
    owner: LogOwner<'_>,
) -> String {
    let mut v = serde_json::json!({
        "action": action,
        "at": at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "detail": detail,
        "prev_hash": prev_hash,
        "seq": seq,
    });
    let map = v.as_object_mut().expect("object");
    match owner {
        LogOwner::Anchor { handle, email } => {
            map.insert("email".into(), serde_json::Value::String(email.to_string()));
            map.insert("handle".into(), serde_json::Value::String(handle.to_string()));
        }
        LogOwner::Token { handle_name, owner_token } => {
            map.insert(
                "handle_name".into(),
                match handle_name {
                    Some(n) => serde_json::Value::String(n.to_string()),
                    None => serde_json::Value::Null,
                },
            );
            map.insert("owner_token".into(), serde_json::Value::String(owner_token.to_string()));
        }
    }
    canonical_json(&v)
}

/// SHA-256 of [`log_entry_canonical`], base64. The stored `entry_hash`.
pub fn log_entry_hash(
    seq: i64,
    at: &DateTime<Utc>,
    action: &str,
    detail: &serde_json::Value,
    prev_hash: &str,
    owner: LogOwner<'_>,
) -> String {
    use base64::Engine;
    use sha2::Digest;
    let canonical = log_entry_canonical(seq, at, action, detail, prev_hash, owner);
    base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(canonical.as_bytes()))
}

/// The anchor as the token mapping keys it: trimmed and lowercased. One person
/// must not be able to end up with two tokens, because then `forget_anchor`
/// deletes one mapping and leaves the other standing — a half-completed erasure
/// that reports success.
fn anchor_key(email: &str) -> String {
    email.trim().to_lowercase()
}

/// The handle with its anchor removed: `PublicAgent` from
/// `PublicAgent.ann@gmail.com`. Works for a domain anchor too, since it strips
/// the anchor it is given rather than guessing where the boundary is.
///
/// Returns None rather than a best guess, and callers store None. That direction
/// matters: a wrong guess here would write the anchor into `handle_name`, which
/// is the one column the shredding depends on being anchor-free. Losing a name
/// from one log line is recoverable; leaking the address into the column that
/// survives erasure is not.
fn strip_anchor(handle: &str, anchor: &str) -> Option<String> {
    let anchor = anchor.trim();
    if anchor.is_empty() {
        return None;
    }
    let tail_start = handle.len().checked_sub(anchor.len() + 1)?;
    if tail_start == 0 || !handle.is_char_boundary(tail_start) {
        return None;
    }
    let (name, tail) = handle.split_at(tail_start);
    if !tail.starts_with('.') || !tail[1..].eq_ignore_ascii_case(anchor) {
        return None;
    }
    Some(name.to_string())
}

/// Is this handle constructed under this anchor? A PAN handle IS
/// `<name>.<anchor>` (§2), so the question is answerable from the strings alone,
/// with no database and no disclosure of whether the handle exists.
///
/// This is a SHAPE check, not the authorization. It exists so a route can refuse
/// "release somebody else's name" before it touches storage, which also keeps
/// such a request from being an existence oracle — a refusal that has not looked
/// anything up cannot leak whether the name is taken. The authoritative check is
/// against the stored row's own anchor, in `release_by_anchor`; both must pass.
pub fn handle_anchors_to(handle: &str, anchor: &str) -> bool {
    strip_anchor(handle.trim(), anchor).is_some()
}

/// The stable opaque token for an anchor, minting one if this anchor has none.
///
/// Random, derived from nothing. A keyed hash of the email would need no table,
/// but an email address is guessable, so an HMAC is opaque only to someone who
/// does not hold the key — and then erasure means destroying a secret shared by
/// every other owner's rows, which any surviving backup undoes. There is nothing
/// to recompute this from.
///
/// Same transaction as the append, and under the same advisory lock, so two
/// concurrent appends for one anchor cannot mint two tokens.
async fn owner_token_for(
    conn: &mut sqlx::PgConnection,
    email: &str,
) -> Result<String, sqlx::Error> {
    let key = anchor_key(email);
    let fresh = format!("ot_{}", Uuid::new_v4().simple());
    // DO UPDATE with a no-op assignment rather than DO NOTHING: DO NOTHING
    // returns no row on conflict, and the existing token is exactly what we need.
    let (token,): (String,) = sqlx::query_as(
        "INSERT INTO log_owner_tokens (email, token) VALUES ($1, $2) \
         ON CONFLICT (email) DO UPDATE SET email = log_owner_tokens.email \
         RETURNING token",
    )
    .bind(&key)
    .bind(&fresh)
    .fetch_one(&mut *conn)
    .await?;
    Ok(token)
}

/// Append to the hash-chained history log (PAN §6). Serialized via an advisory
/// lock; each entry's hash covers the canonical JSON serialization (compact,
/// lexicographically sorted keys) that includes the previous entry's hash.
///
/// `email` is the anchor the entry is logged AGAINST — §6 requires that, so the
/// one party entitled to read the entry can find it — but since migration 0013
/// it is not what gets STORED. The row carries an opaque token instead, and the
/// address lives only in the deletable `log_owner_tokens` mapping.
async fn log_action(
    pool: &PgPool,
    action: &str,
    handle: &str,
    email: &str,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    log_action_tx(&mut tx, action, handle, email, detail).await?;
    tx.commit().await?;
    Ok(())
}

/// The same append, inside a transaction the caller already owns. Re-homing
/// needs the spend-ledger write, the row change and the log entry to be one
/// atomic act — a move that is recorded but not logged, or logged but not
/// spent, is a hole in either §6 or the replay barrier.
async fn log_action_tx(
    conn: &mut sqlx::PgConnection,
    action: &str,
    handle: &str,
    email: &str,
    detail: serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock(4207)").execute(&mut *conn).await?;
    let head: Option<(i64, Option<String>)> =
        sqlx::query_as("SELECT id, entry_hash FROM handle_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    // Pre-chain rows have NULL hashes; the chain geneses with "".
    let prev_hash = head.and_then(|(_, h)| h).unwrap_or_default();
    let at = Utc::now();

    let owner_token = owner_token_for(&mut *conn, email).await?;
    // An action that concerns no handle ('operator', 'discoverable') passes "-",
    // which strips to nothing. Anything else that fails to strip is a
    // malformed handle and loses its name rather than leaking the anchor.
    let handle_name = strip_anchor(handle, email);
    if handle_name.is_none() && handle != "-" {
        log::warn!(
            "[pan] log entry for action '{action}' could not be separated from its \
             anchor; recording it without a handle name rather than storing the anchor"
        );
    }

    let (seq,): (i64,) = sqlx::query_as(
        "INSERT INTO handle_log (at, action, handle_name, owner_token, detail, prev_hash) \
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
    )
    .bind(at)
    .bind(action)
    .bind(&handle_name)
    .bind(&owner_token)
    .bind(&detail)
    .bind(&prev_hash)
    .fetch_one(&mut *conn)
    .await?;

    let entry_hash = log_entry_hash(
        seq,
        &at,
        action,
        &detail,
        &prev_hash,
        LogOwner::Token { handle_name: handle_name.as_deref(), owner_token: &owner_token },
    );

    // `AND entry_hash IS NULL` is the immutability guard. Without it this
    // statement is a general-purpose rewrite of any row by id, and the only
    // thing keeping settled history settled is that the id happens to be the one
    // the INSERT just returned. A future refactor that passes the wrong id, or a
    // retry that runs this twice, must fail rather than overwrite a chained row.
    // Migration 0013 enforces the same rule in the database.
    let rewritten = sqlx::query("UPDATE handle_log SET entry_hash = $1 WHERE id = $2 AND entry_hash IS NULL")
        .bind(&entry_hash)
        .bind(seq)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if rewritten != 1 {
        return Err(sqlx::Error::Protocol(format!(
            "handle_log entry {seq} already had a hash; refusing to rewrite a settled log row"
        )));
    }
    Ok(())
}

/// Can this verified email bind a handle to this listing on email proof
/// alone? Only if it submitted the listing (PAN §4.1). Key-bearing listings
/// need pairing (§4.2) — email proof says nothing about agent control.
async fn check_email_bindable(
    pool: &PgPool,
    email: &str,
    listing_id: Uuid,
) -> Result<(), RegistrarError> {
    let row: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT source, owner_email FROM listings WHERE id = $1")
            .bind(listing_id)
            .fetch_optional(pool)
            .await?;
    match row {
        None => Err(RegistrarError::Invalid("no such listing".into())),
        Some((source, owner)) if source == "manual" && owner.as_deref() == Some(email) => Ok(()),
        Some((source, _)) if source == "manual" => Err(RegistrarError::Unauthorized),
        Some(_) => Err(RegistrarError::Invalid(
            "this agent requires key pairing — proving you received an email doesn't prove you operate it".into(),
        )),
    }
}

/// Claim `<name>.<email>` for a verified email. Full-string uniqueness,
/// first come first served; released handles honor the cooling-off window.
pub async fn claim(
    pool: &PgPool,
    email: &str,
    name: &str,
    listing_id: Option<Uuid>,
    via: &str,
) -> Result<String, RegistrarError> {
    let name = validate_name(name)?;
    if let Some(id) = listing_id {
        check_email_bindable(pool, email, id).await?;
    }
    let handle = format!("{name}.{email}");
    let key = handle.to_lowercase();

    let (cooling,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM handles WHERE handle_key = $1 AND released_at > now() - ($2 || ' days')::interval",
    )
    .bind(&key)
    .bind(COOLING_OFF_DAYS.to_string())
    .fetch_one(pool)
    .await?;
    if cooling > 0 {
        return Err(RegistrarError::Taken(
            "that handle was recently released and is in its cooling-off period".into(),
        ));
    }

    // Migration-out obligation (§7.8): a handle that re-homed away from here is
    // not ours to re-issue. Its owner moved it to another registrar; we serve a
    // referral, we do not hand the name to someone new.
    let (rehomed,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM handles WHERE handle_key = $1 AND rehomed_to IS NOT NULL",
    )
    .bind(&key)
    .fetch_one(pool)
    .await?;
    if rehomed > 0 {
        // §5.6 is unqualified: a registrar that let a name go MUST NOT re-issue
        // it. The owner's route back is not a fresh claim but an undo of the
        // move itself (`rehome_undo`), which restores the original row —
        // otherwise a name moved without the anchor owner's involvement would
        // be unrecoverable here even by its owner.
        return Err(RegistrarError::Taken(
            "that handle re-homed to another registrar and cannot be re-issued here; if you did not \
             authorize the move, sign in and undo it instead"
                .into(),
        ));
    }

    let inserted = sqlx::query(
        "INSERT INTO handles (handle, handle_key, email, listing_id, bind_method, claimed_via) \
         VALUES ($1, $2, $3, $4, CASE WHEN $4::uuid IS NULL THEN NULL ELSE 'email-submitter' END, $5)",
    )
    .bind(&handle)
    .bind(&key)
    .bind(email)
    .bind(listing_id)
    .bind(via)
    .execute(pool)
    .await;
    match inserted {
        Ok(_) => {}
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(RegistrarError::Taken("that handle is taken".into()));
        }
        Err(e) => return Err(e.into()),
    }

    log_action(pool, "claimed", &handle, email, serde_json::json!({ "listing_id": listing_id, "via": via }))
        .await?;
    log::info!("[pan] claimed: {handle} (bound: {})", listing_id.is_some());
    Ok(handle)
}

/// Attach (or re-attach) a handle to an agent listing on email proof
/// (submitter-match only, §4.1). Detaching (listing_id = None) is always
/// allowed for the handle's owner.
pub async fn bind(
    pool: &PgPool,
    email: &str,
    handle: &str,
    listing_id: Option<Uuid>,
) -> Result<(), RegistrarError> {
    if let Some(id) = listing_id {
        check_email_bindable(pool, email, id).await?;
    }
    // One transaction: the rebind, the §4.4 key-change record and the §6 entry
    // commit together. The locked read captures what agent key the name
    // pointed at before, because detaching (or re-pointing to a keyless manual
    // listing) removes the key behind the name too, and leaving THAT change
    // unrecorded would make detach-then-re-pair a way to change keys without a
    // §4.4 entry ever saying so.
    let mut tx = pool.begin().await?;
    let previous_key = bound_agent_key_tx(&mut tx, &handle.trim().to_lowercase()).await?;
    // `rehomed_to IS NULL`: a name that has moved to another registrar is not
    // ours to re-bind. Without it the anchor owner could still change the
    // binding here, writing to a row this registrar gave custody of — and
    // nobody would ever see the result, because `/api/resolve` answers for that
    // handle with a referral (§5.6), not a card. The change would show up only
    // in this registrar's log, as activity on a name it no longer holds.
    let n = sqlx::query(
        "UPDATE handles SET listing_id = $3, \
             bind_method = CASE WHEN $3::uuid IS NULL THEN NULL ELSE 'email-submitter' END \
         WHERE handle_key = lower($1) AND email = $2 AND released_at IS NULL AND rehomed_to IS NULL",
    )
    .bind(handle)
    .bind(email)
    .bind(listing_id)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(RegistrarError::Unauthorized);
    }
    // The new binding is a manual listing or nothing; neither carries an agent
    // key, so any previously bound key just stopped being what the name means.
    if let Some(old) = previous_key.as_deref() {
        record_key_change_tx(&mut tx, &handle.trim().to_lowercase(), old, None, "email-submitter", false)
            .await?;
    }
    log_action_tx(
        &mut tx,
        "bound",
        handle,
        email,
        serde_json::json!({ "listing_id": listing_id, "method": "email-submitter" }),
    )
    .await?;
    tx.commit().await?;
    log::info!("[pan] bound: {handle} -> {listing_id:?} (email-submitter)");
    Ok(())
}

/// One recorded change of the agent key behind a handle (SPEC-NAMING §4.4).
///
/// Pairing never required a handle to be unbound, so one ceremony re-points a
/// trusted name at a brand new key, and everything keyed per public key
/// (reputation, audit chains) silently starts over behind an unchanged name.
/// The party that deceives is the counterparty who READS the name, not the
/// owner who ran the ceremony, so the fix is not a prompt at the owner: it is
/// this record, served to readers on the card and stated on the card page.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct KeyChange {
    pub old_key: String,
    /// None means the binding was removed: the name stopped pointing at any
    /// agent key, which is as much of a break in its record as a new key is.
    pub new_key: Option<String>,
    pub method: String,
    pub changed_at: DateTime<Utc>,
    /// The binding that made this change said the old key is revoked: the
    /// owner reported it leaked (SPEC.md §5.3). Receivers refuse messages
    /// signed by it; a machine move leaves this false.
    pub old_key_revoked: bool,
}

/// The agent key a handle's current binding points at, if its bound listing is
/// an agent record. Read `FOR UPDATE` of the handle row, inside the caller's
/// transaction, so two concurrent rebinds cannot both read the same "before"
/// and record the same change twice (or neither).
async fn bound_agent_key_tx(
    conn: &mut sqlx::PgConnection,
    handle_key: &str,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT (SELECT l.source_id FROM listings l \
                 WHERE l.id = h.listing_id AND l.source IN ('agent','agentmesh')) \
         FROM handles h WHERE h.handle_key = $1 AND h.released_at IS NULL FOR UPDATE OF h",
    )
    .bind(handle_key)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.and_then(|(k,)| k))
}

/// Append a §4.4 key-change row. The caller decides whether a change happened
/// (an old key exists and differs from the new one); this only writes it, in
/// the same transaction as the rebind, so the record and the change it
/// describes cannot exist without each other.
async fn record_key_change_tx(
    conn: &mut sqlx::PgConnection,
    handle_key: &str,
    old_key: &str,
    new_key: Option<&str>,
    method: &str,
    old_key_revoked: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO handle_key_changes (handle_key, old_key, new_key, method, old_key_revoked) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(handle_key)
    .bind(old_key)
    .bind(new_key)
    .bind(method)
    .bind(old_key_revoked)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The §4.4 key history a card serves for a handle: every recorded change of
/// its bound agent key, oldest first, scoped to the CURRENT claim. Changes
/// that predate the active row's `created_at` belong to an earlier claim of
/// the same name (released, cooled off, re-claimed) and describe somebody
/// else's agent, so they are not served.
pub async fn key_history(pool: &PgPool, handle: &str) -> Result<Vec<KeyChange>, RegistrarError> {
    Ok(sqlx::query_as::<_, KeyChange>(
        "SELECT c.old_key, c.new_key, c.method, c.changed_at, c.old_key_revoked \
         FROM handle_key_changes c \
         JOIN handles h ON h.handle_key = c.handle_key \
         WHERE h.handle_key = lower(trim($1)) AND h.released_at IS NULL \
           AND c.changed_at >= h.created_at \
         ORDER BY c.id ASC",
    )
    .bind(handle)
    .fetch_all(pool)
    .await?)
}

/// Start pairing (§4.2): a short single-use code the handle owner relays to
/// whatever software holds their agent's key.
pub async fn pair_start(
    pool: &PgPool,
    email: &str,
    handle: &str,
) -> Result<(String, DateTime<Utc>), RegistrarError> {
    // `rehomed_to IS NULL` for the same reason as `bind`: pairing a key to a
    // name this registrar has handed to another custodian binds nothing anyone
    // can resolve.
    let owned: Option<(String,)> = sqlx::query_as(
        "SELECT handle FROM handles WHERE handle_key = lower($1) AND email = $2 AND released_at IS NULL AND rehomed_to IS NULL",
    )
    .bind(handle)
    .bind(email)
    .fetch_optional(pool)
    .await?;
    let Some((display_handle,)) = owned else {
        return Err(RegistrarError::Unauthorized);
    };

    // Short, copyable, unambiguous: XXX-XXX from A-Z/2-9 minus 0/O/1/I.
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    // 32 letters divide 256 evenly, so each byte picks one with no bias.
    let bytes = random_bytes::<6>();
    let chars: String =
        bytes.iter().take(6).map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char).collect();
    let code = format!("{}-{}", &chars[..3], &chars[3..]);
    let expires = Utc::now() + chrono::Duration::minutes(10);
    sqlx::query("INSERT INTO pairing_codes (code, handle, email, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(&code)
        .bind(&display_handle)
        .bind(email)
        .bind(expires)
        .execute(pool)
        .await?;
    log::info!("[pan] pairing started for {display_handle}");
    Ok((code, expires))
}

/// Complete pairing (§4.2). Unauthenticated by design: the code proves the
/// handle owner initiated it; the signature over the canonical string
/// `pan-pair-v1:<code>:<agent-id>` proves agent control. The binding is
/// the intersection of the two proofs.
pub async fn pair_complete(
    pool: &PgPool,
    code: &str,
    agent_id: &str,
    signature_b64: &str,
) -> Result<String, RegistrarError> {
    use base64::Engine;

    let code = code.trim().to_uppercase();
    let agent_id = agent_id.trim();

    // The code is spent ONLY by a request that also carries a valid signature,
    // and the whole act is one transaction. Burning it first meant anyone who
    // saw a code — they are relayed by humans, pasted into chats — could
    // invalidate it with one unsigned request and force the owner to start over.
    let mut tx = pool.begin().await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT handle, email FROM pairing_codes \
         WHERE code = $1 AND used_at IS NULL AND expires_at > now() FOR UPDATE",
    )
    .bind(&code)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((handle, email)) = row else {
        return Err(RegistrarError::Invalid("unknown, used, or expired pairing code".into()));
    };

    let sig = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| RegistrarError::Invalid("signature is not valid base64".into()))?;
    let msg = format!("pan-pair-v1:{code}:{agent_id}");
    let kp = nkeys::KeyPair::from_public_key(agent_id)
        .map_err(|_| RegistrarError::Invalid("agent_id is not a valid public key".into()))?;
    kp.verify(msg.as_bytes(), &sig)
        .map_err(|_| RegistrarError::Invalid("signature does not verify against the agent key".into()))?;

    let spent = sqlx::query("UPDATE pairing_codes SET used_at = now() WHERE code = $1 AND used_at IS NULL")
        .bind(&code)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    if spent != 1 {
        return Err(RegistrarError::Invalid("unknown, used, or expired pairing code".into()));
    }

    // What key did this name point at before this pairing? Read under the same
    // transaction, with the handle row locked, BEFORE the rebind below. A
    // pairing that re-points a bound name to a different key is legitimate
    // (§4.4: re-pairing after a key loss is exactly what the ceremony is for),
    // and it is also the one act that lets a name keep its appearance while
    // the per-key record behind it starts over, so the change is recorded
    // where readers of the name can see it.
    let handle_key_folded = handle.to_lowercase();
    let previous_key = bound_agent_key_tx(&mut tx, &handle_key_folded).await?;

    // The signature is the agent record's authorization. There is no prior
    // directory to look the agent up in (PAN §4.1): the proven key IS the
    // record. Create or refresh a minimal record and bind to it.
    // The anchor the pairing code was issued under, taken off the end (see
    // split_handle): a dotted name or a dotted email must not be recorded as
    // the wrong listing.
    let stripped = strip_anchor(&handle, &email);
    let name = stripped.as_deref().unwrap_or(handle.as_str());
    let (listing_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO listings (source, source_id, name, description, manifest, specialties, protocol) \
         VALUES ('agent', $1, $2, '', $3, '{}', 'mesh') \
         ON CONFLICT (source, source_id) DO UPDATE SET name = EXCLUDED.name, updated_at = now() \
         RETURNING id",
    )
    .bind(agent_id)
    .bind(name)
    .bind(serde_json::json!({ "id": agent_id }))
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE handles SET listing_id = $2, bind_method = 'agent-key' \
         WHERE handle_key = lower($1) AND released_at IS NULL",
    )
    .bind(&handle)
    .bind(listing_id)
    .execute(&mut *tx)
    .await?;
    // §4.4: a rebind to a DIFFERENT key is recorded where readers can see it.
    // The first binding of a fresh handle is not a change; re-pairing the same
    // key (a machine move, a retry) is not either.
    let rebound_from = previous_key.as_deref().filter(|k| *k != agent_id);
    if let Some(old) = rebound_from {
        record_key_change_tx(&mut tx, &handle_key_folded, old, Some(agent_id), "agent-key", false).await?;
    }
    let mut detail =
        serde_json::json!({ "listing_id": listing_id, "method": "agent-key", "agent_id": agent_id });
    if let Some(old) = rebound_from {
        // The owner's §6 history says it too: this binding replaced a key.
        detail["previous_agent_id"] = serde_json::Value::String(old.to_string());
    }
    log_action_tx(&mut tx, "bound", &handle, &email, detail).await?;
    tx.commit().await?;
    log::info!("[pan] bound: {handle} -> {listing_id} (agent-key, {agent_id})");
    Ok(handle)
}

/// How long a signed re-home statement stays usable. It is a bearer
/// authorization, so it should live just long enough for a human to run the
/// two-step move (out at the old registrar, in at the new one) and no longer.
const REHOME_MAX_AGE_SECS: i64 = 900;

/// Split a handle into (name, anchor email) where no anchor is on record: a
/// handle arriving from another registrar.
///
/// SPEC-NAMING §2 rule 1: nobody parses handles. A name may hold dots and so
/// may the local part of an email, so `genesis.jeff.s@x.com` is either name
/// `genesis` under `jeff.s@x.com` or name `genesis.jeff` under `s@x.com`, and
/// only the claim says which. Splitting at the last dot before the '@' (what
/// this used to do, for re-homing and for listing names) read the first as the
/// second and attributed the handle to the wrong address, which is the anchor
/// the whole trust model hangs on. Where the anchor is on record, callers now
/// take it off the end with `strip_anchor` instead of calling this.
///
/// With the anchor said, it is taken off the end the same way and must fit.
/// Without it, the handle is split only if it reads one way, which is when
/// exactly one dot comes before the '@': the anchor is then everything after
/// the name's dot. A handle that reads more than one way is refused rather
/// than guessed, with the reason, so the caller can say which email anchors it.
fn split_handle<'a>(handle: &'a str, anchor: Option<&str>) -> Result<(&'a str, &'a str), RegistrarError> {
    if let Some(a) = anchor.map(str::trim).filter(|a| !a.is_empty()) {
        let name_len = strip_anchor(handle, a).map(|n| n.len()).ok_or_else(|| {
            RegistrarError::Invalid("the handle does not end in the anchor email given with it".into())
        })?;
        return Ok((&handle[..name_len], &handle[name_len + 1..]));
    }
    let at = handle.find('@').ok_or_else(|| RegistrarError::Invalid("handle has no anchor email".into()))?;
    let dots: Vec<usize> = handle[..at].match_indices('.').map(|(i, _)| i).collect();
    match dots.as_slice() {
        [] => Err(RegistrarError::Invalid("handle has no anchor email".into())),
        [dot] => Ok((&handle[..*dot], &handle[*dot + 1..])),
        _ => Err(RegistrarError::Invalid(
            "this handle can be read more than one way, because its name or its email has a dot in it; say which email anchors it (the `anchor` field)".into(),
        )),
    }
}

/// A registrar URL as we compare and store it: trimmed, no trailing slash,
/// lowercased. Must be http(s) and of sane length — this string is served in
/// referrals that other people's resolvers follow.
fn normalize_registrar_url(raw: &str) -> Result<String, RegistrarError> {
    let u = raw.trim().trim_end_matches('/').to_lowercase();
    if u.is_empty() || u.len() > 255 {
        return Err(RegistrarError::Invalid("registrar URL must be 1-255 characters".into()));
    }
    if !u.starts_with("https://") && !u.starts_with("http://") {
        return Err(RegistrarError::Invalid("registrar URL must be http(s)".into()));
    }
    Ok(u)
}

fn is_loopback_url(u: &str) -> bool {
    u.starts_with("http://localhost") || u.starts_with("https://localhost")
        || u.starts_with("http://127.") || u.starts_with("https://127.")
        || u.starts_with("http://[::1]") || u.starts_with("https://[::1]")
}

/// Is this address one the public internet routes to? Everything else — the
/// metadata service, RFC1918, carrier NAT, link-local, the unspecified address,
/// IPv4-mapped IPv6 — is somebody's internal network, and this service must not
/// be talked into fetching from it. `std`'s `is_global` is still unstable, so
/// the ranges are spelled out.
fn ip_is_global(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_unspecified()            // 0.0.0.0
                || v4.is_loopback()          // 127/8
                || v4.is_private()           // 10/8, 172.16/12, 192.168/16
                || v4.is_link_local()        // 169.254/16 — the metadata service
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (o[0] == 100 && (64..128).contains(&o[1]))   // 100.64/10 CGNAT
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)      // 192.0.0/24
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))  // 198.18/15 benchmarking
                || o[0] >= 240)                                 // 240/4 reserved
        }
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return ip_is_global(std::net::IpAddr::V4(mapped));
            }
            let s = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.to_ipv4().is_some()          // ::a.b.c.d (deprecated compat form)
                || (s[0] & 0xfe00) == 0xfc00       // fc00::/7 unique local
                || (s[0] & 0xffc0) == 0xfe80       // fe80::/10 link local
                || (s[0] == 0x2001 && s[1] == 0x0db8)) // documentation
        }
    }
}

/// Guard an outbound fetch to a peer registrar. The peer allowlist (§5.6
/// check 5, `PAN_PEERS`) is the real control; this is the depth behind it, and
/// it is a real address check rather than a string prefix test: `169.254.169.254`,
/// `http://2130706433`, `http://0177.0.0.1`, `[::ffff:127.0.0.1]` and
/// `http://jenkins/` all read as ordinary hostnames to a prefix test and all
/// point inward.
///
/// The URL is parsed by the same WHATWG parser the HTTP client uses, so the
/// decimal and octal literal forms normalize to the address they mean before we
/// judge them, and any hostname is resolved and every answer checked. DNS can
/// still change between this check and the client's own lookup; the allowlist,
/// not this function, is what makes that not matter.
async fn check_outbound_url(url: &str, allow_loopback: bool) -> Result<(), RegistrarError> {
    let refuse = |why: &str| {
        RegistrarError::Invalid(format!("this registrar will not fetch from that address ({why})"))
    };
    let parsed = reqwest::Url::parse(url).map_err(|_| refuse("not a URL"))?;
    if parsed.scheme() != "https" && !(allow_loopback && parsed.scheme() == "http") {
        return Err(refuse("a peer registrar must be reached over https"));
    }
    let host = parsed.host_str().ok_or_else(|| refuse("no host"))?.to_string();
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        if ip.is_loopback() && allow_loopback {
            return Ok(());
        }
        if !ip_is_global(ip) {
            return Err(refuse("not a globally routable address"));
        }
        return Ok(());
    }
    let lower = host.to_lowercase();
    if allow_loopback && lower == "localhost" {
        return Ok(());
    }
    // A single-label name ("jenkins", "registry") is an internal name by
    // construction, as are the reserved internal suffixes.
    if !lower.contains('.')
        || lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.ends_with(".localhost")
        || lower.ends_with(".home.arpa")
    {
        return Err(refuse("an internal hostname"));
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((lower.as_str(), port))
        .await
        .map_err(|_| refuse("the name does not resolve"))?
        .collect();
    if addrs.is_empty() {
        return Err(refuse("the name does not resolve"));
    }
    if !addrs.iter().all(|a| ip_is_global(a.ip())) {
        return Err(refuse("the name resolves to an address inside a private network"));
    }
    Ok(())
}

/// A peer registrar: one this registrar is willing to accept a migration IN
/// from (§5.6 check 5). Peers are CONFIGURED, never taken from the request —
/// `old_registrar` arrives on an unauthenticated call, so treating it as the
/// source of truth means an attacker stands up a "registrar" that agrees with
/// whatever they claim, and every check passes.
///
/// `PAN_PEERS` is a comma-separated list of origins, each optionally pinned to
/// the Ed25519 key its referrals must be signed by:
///
/// ```text
/// PAN_PEERS="https://naming.example.org,https://other.example|UC3ABC…"
/// ```
///
/// A pinned key is the stronger form: without one, the peer's key is fetched
/// from its own `/api/registrar-key` and the trust in it comes from TLS plus
/// membership of this list.
#[derive(Clone, Debug)]
pub struct Peer {
    pub origin: String,
    pub pinned_key: Option<String>,
}

/// The configured peer set. Empty means migration IN is closed: §5.6 check 5
/// cannot be satisfied by asking a stranger.
pub fn configured_peers() -> Vec<Peer> {
    std::env::var("PAN_PEERS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            let (url, key) = match entry.split_once('|') {
                Some((u, k)) => (u, Some(k.trim().to_string()).filter(|s| !s.is_empty())),
                None => (entry, None),
            };
            match normalize_registrar_url(url) {
                Ok(origin) => Some(Peer { origin, pinned_key: key }),
                Err(_) => {
                    log::error!("[pan] ignoring unusable PAN_PEERS entry: {entry}");
                    None
                }
            }
        })
        .collect()
}

/// Which configured peer is this, if any.
///
/// When `PAN_PEERS` names anyone, membership is the whole test: an exact
/// normalized match or nothing. The one other way in is the local
/// two-registrar test rig, and it is bounded twice over — it applies only when
/// NO peers are configured, and only when this registrar's own URL is loopback,
/// i.e. it is a process on somebody's laptop rather than a deployment. A
/// deployed registrar has a public PAN_SELF_URL and can never take that branch;
/// a rig that wants to prove the allowlist works sets PAN_PEERS and the branch
/// switches off.
fn peer_for(old: &str, self_url: &str) -> Result<Peer, RegistrarError> {
    let peers = configured_peers();
    if let Some(p) = peers.iter().find(|p| p.origin == old) {
        return Ok(p.clone());
    }
    if peers.is_empty() && is_loopback_url(old) && is_loopback_url(self_url) {
        return Ok(Peer { origin: old.to_string(), pinned_key: None });
    }
    Err(RegistrarError::Invalid(if peers.is_empty() {
        "this registrar has no peer registrars configured, so it cannot confirm a handle was \
         released to it and will not accept a migration in"
            .into()
    } else {
        "that registrar is not a configured peer of this one, so its word about a released handle \
         is not something this registrar can act on"
            .into()
    }))
}

/// One HTTP client for peer traffic: an 8-second timeout and NO redirect
/// following, so a peer cannot bounce us somewhere we did not check.
fn peer_http() -> Result<&'static reqwest::Client, RegistrarError> {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(8))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok()
        })
        .as_ref()
        .ok_or_else(|| RegistrarError::Invalid("could not build an http client".into()))
}

/// Fetch JSON from a peer with a hard ceiling on how much we will read. A
/// peer is a party we chose, but "chose" is not "trusts with our memory": a
/// chunked response with no content-length would otherwise be buffered whole
/// until the timeout. `what` names the document for the error message.
async fn peer_json(url: &str, what: &str) -> Result<serde_json::Value, RegistrarError> {
    const MAX_BYTES: usize = 256 * 1024;
    let mut res = peer_http()?
        .get(url)
        .send()
        .await
        .map_err(|_| RegistrarError::Invalid(format!("could not reach the old registrar for {what}")))?;
    if !res.status().is_success() {
        return Err(RegistrarError::Invalid(format!(
            "the old registrar answered HTTP {} for {what}, so it has released nothing to us",
            res.status().as_u16()
        )));
    }
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = res
        .chunk()
        .await
        .map_err(|_| RegistrarError::Invalid(format!("the old registrar's {what} ended early")))?
    {
        if body.len() + chunk.len() > MAX_BYTES {
            return Err(RegistrarError::Invalid(format!(
                "the old registrar's {what} is larger than this registrar will read"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|_| RegistrarError::Invalid(format!("the old registrar's {what} was not JSON")))
}

/// The signing keys a peer publishes at `/api/registrar-key` (§5.3), cached in
/// process for a few minutes. Accepts both the shape this registrar serves
/// today (`keys: ["U…"]`) and the key-set shape with ids, so a peer on either
/// version can be corroborated against.
async fn peer_signing_keys(peer: &Peer, allow_loopback: bool) -> Result<Vec<String>, RegistrarError> {
    if let Some(k) = &peer.pinned_key {
        return Ok(vec![k.clone()]);
    }
    use std::sync::{Mutex, OnceLock};
    use std::time::Instant;
    /// peer origin -> (when fetched, the keys it published then)
    type KeyCache = std::collections::HashMap<String, (Instant, Vec<String>)>;
    static CACHE: OnceLock<Mutex<KeyCache>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(KeyCache::new()));
    if let Ok(map) = cache.lock() {
        if let Some((at, keys)) = map.get(&peer.origin) {
            if at.elapsed().as_secs() < PEER_KEY_TTL_SECS {
                return Ok(keys.clone());
            }
        }
    }

    let url = format!("{}/api/registrar-key", peer.origin);
    check_outbound_url(&url, allow_loopback).await?;
    let body = peer_json(&url, "its signing key").await?;
    let mut keys: Vec<String> = Vec::new();
    for field in ["keys", "key_set"] {
        for item in body.get(field).and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) {
            let candidate = item
                .as_str()
                .map(str::to_string)
                .or_else(|| item.get("key").and_then(|v| v.as_str()).map(str::to_string));
            if let Some(k) = candidate {
                let k = k.trim().to_string();
                if nkeys::KeyPair::from_public_key(&k).is_ok() && !keys.contains(&k) {
                    keys.push(k);
                }
            }
        }
    }
    if keys.is_empty() {
        return Err(RegistrarError::Invalid(
            "the old registrar publishes no usable signing key, so its referral cannot be verified".into(),
        ));
    }
    if let Ok(mut map) = cache.lock() {
        map.insert(peer.origin.clone(), (Instant::now(), keys.clone()));
    }
    Ok(keys)
}

/// The canonical string a re-home statement signs (§5.6). The agent's key
/// signs it; both registrars verify against that key.
fn rehome_msg(handle: &str, new_registrar: &str, timestamp: &str) -> String {
    format!("pan-rehome-v1:{handle}:{new_registrar}:{timestamp}")
}

/// Reject a statement whose signed timestamp is stale (or implausibly far in
/// the future — clock skew cuts both ways). Without this a captured statement
/// is good forever.
fn check_rehome_freshness(timestamp: &str) -> Result<(), RegistrarError> {
    let ts = DateTime::parse_from_rfc3339(timestamp.trim())
        .map_err(|_| RegistrarError::Invalid("re-home timestamp must be RFC 3339".into()))?
        .with_timezone(&Utc);
    if (Utc::now() - ts).num_seconds().abs() > REHOME_MAX_AGE_SECS {
        return Err(RegistrarError::Invalid(
            "re-home statement is outside the accepted time window — sign a fresh one".into(),
        ));
    }
    Ok(())
}

/// The ledger key for a statement: the exact bytes that were signed, plus the
/// signature. Two different signatures over the same canonical are two
/// different bearer tokens, so both are covered.
///
/// The handle is canonicalized (lowercased, trimmed) here and NOWHERE ELSE, so
/// both sides of a move hash the same thing. Hashing the caller's spelling let
/// a spent statement be replayed by changing its capitalization: the signature
/// still verified against the stored display handle, the lookup was already
/// case-folded, and only the ledger key came out different.
fn statement_hash(handle: &str, new_registrar: &str, timestamp: &str, signature_b64: &str) -> String {
    use base64::Engine;
    use sha2::Digest;
    let canonical_handle = handle.trim().to_lowercase();
    let digest = sha2::Sha256::digest(
        format!("{}|{}", rehome_msg(&canonical_handle, new_registrar, timestamp), signature_b64.trim())
            .as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest)
}

/// Claim a statement inside the caller's transaction: insert first and let the
/// primary key decide. Returns false when it was already spent.
///
/// Checking with a SELECT and writing later left a window in which two
/// concurrent submissions of one statement both read "unspent" and both acted;
/// the unique violation IS the check, so there is nothing to race.
async fn try_spend_statement(
    conn: &mut sqlx::PgConnection,
    hash: &str,
    handle: &str,
    agent_id: &str,
    action: &str,
) -> Result<bool, RegistrarError> {
    let done = sqlx::query(
        "INSERT INTO rehome_statements (statement_hash, handle, agent_id, action) \
         VALUES ($1, $2, $3, $4) ON CONFLICT (statement_hash) DO NOTHING",
    )
    .bind(hash)
    .bind(handle)
    .bind(agent_id)
    .bind(action)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// The signed referral a registrar owes for a handle that left it (§5.6, §7.8).
///
/// Everything a corroborating registrar relies on is INSIDE the signed bytes,
/// including `from` — this registrar's own URL. Without `from`, a referral
/// signed by any registrar for a handle it legitimately gave up could be
/// replayed as though a different registrar had said it, and the new custodian
/// would be corroborating against the wrong party.
pub fn build_referral(
    handle: &str,
    new_registrar: &str,
    self_url: Option<&str>,
    operator: Option<&str>,
) -> serde_json::Value {
    let now = Utc::now();
    serde_json::json!({
        "handle": handle,
        "registrar": new_registrar,
        "from": self_url,
        "operator": operator,
        "issued_at": now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
        "expires_at": (now + chrono::Duration::seconds(card_ttl_secs()))
            .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
    })
}

/// What a corroborated referral told us. `operator` rides along so the new
/// custodian can satisfy §5.1's REQUIRED operator record without inventing one.
#[derive(Debug)]
struct Corroboration {
    operator: Option<String>,
}

/// Is a signed document still inside its validity window? A missing
/// `expires_at` is a document from a registrar that predates the window; the
/// signature requirement already excludes strangers, so this is not the place
/// to fail closed on version skew.
fn within_validity(doc: &serde_json::Value) -> bool {
    match doc.get("expires_at").and_then(|v| v.as_str()) {
        None => true,
        Some(ts) => DateTime::parse_from_rfc3339(ts.trim())
            .map(|t| t.with_timezone(&Utc) > Utc::now() - chrono::Duration::seconds(60))
            .unwrap_or(false),
    }
}

/// Ask the OLD registrar whether it agrees it gave this handle up, and gave it
/// up TO US (§5.6/§7.8). This is the check that makes a re-home statement mean
/// something: on its own the statement is self-signed by whoever holds a key,
/// and it names its own destination, so accepting one without corroboration
/// lets anybody mint any handle at any registrar — including names they never
/// held, names anchored to other people's email addresses, and names sitting
/// in another registrar's cooling-off window. The losing registrar's referral
/// is the second party to the story.
///
/// It is deliberately the referral (a public GET) rather than a new signed
/// hand-off endpoint: the referral already exists in §5.6, so no conforming
/// registrar has to add anything to be migrated away from. The order is
/// therefore fixed — out first, then in.
async fn corroborate_with_old_registrar(
    old_registrar: &str,
    handle: &str,
    self_url: &str,
) -> Result<Corroboration, RegistrarError> {
    let old = normalize_registrar_url(old_registrar)?;

    // (i) WHO we are willing to believe. `old_registrar` arrives on an
    // unauthenticated request, so it is attacker-chosen: standing up
    // https://evil.example/api/resolve that answers "yes, released to you" is
    // one afternoon's work, and it satisfies every other check. A referral is
    // only evidence when it comes from a party this registrar already decided
    // to peer with, so the allowlist is the check and the rest is depth.
    let peer = peer_for(&old, self_url)?;
    let rig = is_loopback_url(&old) && is_loopback_url(self_url);

    // (ii) WHERE we will fetch from. https (so DNS and TLS name the peer we
    // think we are talking to) and a globally routable address.
    check_outbound_url(&old, rig).await?;

    let url = format!("{old}/api/resolve?handle={}", urlencoding_minimal(handle));
    let body = peer_json(&url, "that handle's resolution").await?;
    // No referral means the old registrar still holds the name: either the
    // migration OUT has not been recorded there yet (§5.6 fixes the order —
    // out first, then in), or it never held it at all.
    let referral = body.get("referral").ok_or_else(|| {
        RegistrarError::Invalid(
            "the old registrar still answers for that handle itself, so it has not released it to \
             us — record the migration out there first (SPEC-NAMING §5.6: out first, then in)"
                .into(),
        )
    })?;

    // (iii) WHETHER the peer actually said it. §5.6/§7.8 call for a SIGNED
    // referral, and this is why: bare JSON off a socket is not a second party
    // to the story, it is whatever answered. Verified against the keys the peer
    // publishes out of band (§5.3), not against the key the response declares.
    let sig_b64 = body
        .get("registrar_sig")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            RegistrarError::Invalid(
                "the old registrar served an UNSIGNED referral; a signed referral is what makes a \
                 migration in corroborated (SPEC-NAMING §5.6, §7.8)"
                    .into(),
            )
        })?;
    let sig = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(sig_b64.trim())
            .map_err(|_| RegistrarError::Invalid("the referral signature is not valid base64".into()))?
    };
    let bytes = canonical_json(referral).into_bytes();
    let keys = peer_signing_keys(&peer, rig).await?;
    let verified = keys.iter().any(|k| {
        nkeys::KeyPair::from_public_key(k)
            .map(|kp| kp.verify(&bytes, &sig).is_ok())
            .unwrap_or(false)
    });
    if !verified {
        return Err(RegistrarError::Invalid(
            "the referral is not signed by a key the old registrar publishes — it is not that \
             registrar's word"
                .into(),
        ));
    }
    if !within_validity(referral) {
        return Err(RegistrarError::Invalid(
            "the old registrar's referral has expired — resolve the handle there again".into(),
        ));
    }

    // (iv) WHAT it says. The signed bytes must name this registrar as the
    // destination, name the peer we asked as their author, and be about the
    // handle we asked about.
    let says = |k: &str| referral.get(k).and_then(|v| v.as_str()).map(str::to_string);
    let destination = says("registrar").ok_or_else(|| {
        RegistrarError::Invalid("the old registrar's referral names no destination".into())
    })?;
    if normalize_registrar_url(&destination)? != normalize_registrar_url(self_url)? {
        return Err(RegistrarError::Invalid(
            "the old registrar refers this handle somewhere else — it was not released to us".into(),
        ));
    }
    match says("from") {
        Some(from) if normalize_registrar_url(&from)? == old => {}
        Some(_) => {
            return Err(RegistrarError::Invalid(
                "the referral was issued by a different registrar than the one it came from — a \
                 referral is not transferable"
                    .into(),
            ))
        }
        None => {
            return Err(RegistrarError::Invalid(
                "the old registrar's referral does not say who issued it, so it could have been \
                 written for a different registrar"
                    .into(),
            ))
        }
    }
    match says("handle") {
        Some(h) if h.trim().to_lowercase() == handle.trim().to_lowercase() => {}
        _ => {
            return Err(RegistrarError::Invalid(
                "the old registrar's referral is about a different handle".into(),
            ))
        }
    }

    Ok(Corroboration {
        operator: referral
            .get("operator")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty() && s.chars().count() <= 80),
    })
}

/// Percent-encode the few characters that break a query string. Handles are
/// `<name>.<email>`; '+' and '&' and spaces are the ones that matter.
fn urlencoding_minimal(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' | '@' => c.to_string(),
            other => other.to_string().bytes().map(|b| format!("%{b:02X}")).collect(),
        })
        .collect()
}

fn verify_rehome_sig(
    agent_id: &str,
    handle: &str,
    new_registrar: &str,
    timestamp: &str,
    signature_b64: &str,
) -> Result<(), RegistrarError> {
    use base64::Engine;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| RegistrarError::Invalid("signature is not valid base64".into()))?;
    let kp = nkeys::KeyPair::from_public_key(agent_id.trim())
        .map_err(|_| RegistrarError::Invalid("agent_id is not a valid public key".into()))?;
    kp.verify(rehome_msg(handle, new_registrar, timestamp).as_bytes(), &sig)
        .map_err(|_| RegistrarError::Invalid("re-home signature does not verify against the agent key".into()))
}

/// Migration OUT (§5.6, §7.8): the OLD custodian executes a key-signed
/// departure. The statement must verify against the key the handle is bound
/// to; on success the handle is marked re-homed (resolution now referrals,
/// re-issue is refused) and the move is logged. A conforming registrar cannot
/// refuse this — a name its owner has moved is not the registrar's to keep.
pub async fn rehome_out(
    pool: &PgPool,
    handle: &str,
    new_registrar: &str,
    agent_id: &str,
    timestamp: &str,
    signature_b64: &str,
) -> Result<RehomedOut, RegistrarError> {
    let new_registrar = &normalize_registrar_url(new_registrar)?;
    check_rehome_freshness(timestamp)?;
    let stmt = statement_hash(handle, new_registrar, timestamp, signature_b64);

    // One transaction for the whole act: the row is locked while we decide, the
    // statement is spent, the change is written and the §6 entry appended
    // together, or none of it happens.
    let mut tx = pool.begin().await?;
    /// (display handle, bound listing, anchor, where it already went, undo hold)
    type OutRow = (String, Option<Uuid>, String, Option<String>, Option<DateTime<Utc>>);
    let row: Option<OutRow> = sqlx::query_as(
        "SELECT handle, listing_id, email, rehomed_to, rehome_hold_until FROM handles \
         WHERE handle_key = lower(trim($1)) AND released_at IS NULL FOR UPDATE",
    )
    .bind(handle)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((handle, listing_id, email, rehomed_to, hold_until)) = row else {
        return Err(RegistrarError::Invalid("this registrar does not hold that handle".into()));
    };
    // A handle that already left is no longer ours to point anywhere. Without
    // this, the same key could keep re-pointing the destination after the move,
    // changing what other registrars corroborate against.
    if rehomed_to.is_some() {
        return Err(RegistrarError::Invalid(
            "that handle has already re-homed; this registrar no longer decides where it lives".into(),
        ));
    }
    // The anchor owner reversed a move on this handle (§5.6 undo). A key alone
    // does not get to immediately redo what the mailbox owner just undid.
    if let Some(until) = hold_until {
        if until > Utc::now() {
            return Err(RegistrarError::Invalid(format!(
                "the anchor owner reversed a re-home of this handle; re-homing is paused until {} \
                 — the owner can lift the hold from their own session",
                until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            )));
        }
    }
    // The statement must be signed by the key the handle is bound to.
    let bound_key: Option<(String,)> = match listing_id {
        Some(id) => sqlx::query_as("SELECT source_id FROM listings WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?,
        None => None,
    };
    let Some((bound_key,)) = bound_key else {
        return Err(RegistrarError::Invalid("handle is not bound to an agent key; cannot re-home".into()));
    };
    if bound_key.trim() != agent_id.trim() {
        return Err(RegistrarError::Unauthorized);
    }
    verify_rehome_sig(agent_id, &handle, new_registrar, timestamp, signature_b64)?;

    if !try_spend_statement(&mut tx, &stmt, &handle, agent_id.trim(), "rehome-out").await? {
        return Err(RegistrarError::Invalid(
            "this re-home statement has already been used — sign a fresh one".into(),
        ));
    }

    let moved = sqlx::query(
        "UPDATE handles SET rehomed_to = $2, rehomed_at = now() \
         WHERE handle_key = lower(trim($1)) AND released_at IS NULL AND rehomed_to IS NULL",
    )
    .bind(&handle)
    .bind(new_registrar)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if moved != 1 {
        return Err(RegistrarError::Invalid(
            "that handle could not be re-homed; resolve it here and try again".into(),
        ));
    }
    // Logged against the handle's OWN anchor, not an empty string: the §6
    // history is owner-scoped (log_entries filters by email), so an entry
    // logged under "" is invisible to the one person entitled to see it — the
    // owner could not tell from their own history that their name had left.
    log_action_tx(
        &mut tx,
        "rehomed",
        &handle,
        &email,
        serde_json::json!({ "new_registrar": new_registrar, "agent_id": agent_id, "timestamp": timestamp }),
    )
    .await?;
    tx.commit().await?;
    log::info!("[pan] rehomed out: {handle} -> {new_registrar}");
    Ok(RehomedOut {
        handle,
        anchor: email,
        new_registrar: new_registrar.clone(),
        undo_until: Utc::now() + chrono::Duration::days(REHOME_UNDO_DAYS),
    })
}

/// What a completed migration OUT tells the API layer: enough to notify the
/// anchor owner that their name left and by when they can reverse it. The move
/// itself is authorized by a key, so the mailbox owner is not a party to it —
/// the notification is how they find out in time to use the undo.
pub struct RehomedOut {
    pub handle: String,
    pub anchor: String,
    pub new_registrar: String,
    pub undo_until: DateTime<Utc>,
}

/// Undo a migration OUT (§5.6), under the anchor owner's own verified session.
///
/// A re-home is authorized by the agent key alone: whoever holds it — a hosted
/// agent service, a stolen laptop, anyone who ever ran the agent — can move a
/// name permanently, and the person who proved the mailbox is not consulted.
/// The move stays key-authorized (§5.6 says the key signs, and §7.8 says a
/// registrar that will not let a name leave is not conforming), so the owner's
/// standing is expressed as a reversal inside a window rather than as a second
/// signature on the way out. `resume` lifts the post-undo hold instead, for an
/// owner who does want to move after all.
pub async fn rehome_undo(
    pool: &PgPool,
    email: &str,
    handle: &str,
    resume: bool,
) -> Result<String, RegistrarError> {
    let mut tx = pool.begin().await?;
    if resume {
        let row: Option<(String,)> = sqlx::query_as(
            "UPDATE handles SET rehome_hold_until = NULL \
             WHERE handle_key = lower(trim($1)) AND email = $2 AND released_at IS NULL RETURNING handle",
        )
        .bind(handle)
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((display,)) = row else {
            return Err(RegistrarError::Unauthorized);
        };
        log_action_tx(&mut tx, "rehome-hold-lifted", &display, email, serde_json::json!({})).await?;
        tx.commit().await?;
        log::info!("[pan] rehome hold lifted: {display}");
        return Ok(display);
    }

    let row: Option<(String, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT handle, rehomed_to, rehomed_at FROM handles \
         WHERE handle_key = lower(trim($1)) AND email = $2 AND rehomed_to IS NOT NULL \
         ORDER BY created_at DESC LIMIT 1 FOR UPDATE",
    )
    .bind(handle)
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((display, Some(destination), rehomed_at)) = row else {
        return Err(RegistrarError::Invalid(
            "that handle has not re-homed away from this registrar under your anchor".into(),
        ));
    };
    let Some(at) = rehomed_at else {
        return Err(RegistrarError::Invalid(
            "this move predates the undo window and can only be reversed by the registrar operator".into(),
        ));
    };
    if Utc::now() - at > chrono::Duration::days(REHOME_UNDO_DAYS) {
        return Err(RegistrarError::Invalid(format!(
            "the {REHOME_UNDO_DAYS}-day window to reverse this move closed on {}",
            (at + chrono::Duration::days(REHOME_UNDO_DAYS))
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        )));
    }
    let hold_until = Utc::now() + chrono::Duration::days(REHOME_HOLD_DAYS);
    sqlx::query(
        "UPDATE handles SET rehomed_to = NULL, rehomed_at = NULL, rehome_hold_until = $3 \
         WHERE handle_key = lower(trim($1)) AND email = $2",
    )
    .bind(&display)
    .bind(email)
    .bind(hold_until)
    .execute(&mut *tx)
    .await?;
    log_action_tx(
        &mut tx,
        "rehome-undone",
        &display,
        email,
        serde_json::json!({ "was_rehomed_to": destination, "hold_until": hold_until }),
    )
    .await?;
    tx.commit().await?;
    log::info!("[pan] rehome undone by anchor owner: {display} (was -> {destination})");
    Ok(display)
}

/// Migration IN (§5.6): the NEW custodian accepts a key-signed statement and
/// takes custody, binding the handle to the same key with provenance
/// `rehomed:<old-registrar>`. The signature proves key control; no email
/// ceremony is repeated (the name and its anchor are unchanged — only the
/// custodian moved).
pub async fn rehome_in(
    pool: &PgPool,
    handle: &str,
    old_registrar: &str,
    agent_id: &str,
    timestamp: &str,
    new_registrar: &str,
    signature_b64: &str,
    self_url: &str,
    // Which email anchors the handle, needed only when the handle reads more
    // than one way (see split_handle). Not signed: the signature covers the
    // handle, and the anchor must be a suffix of it, so the only freedom it
    // gives is choosing between readings the handle already allows.
    anchor: Option<&str>,
) -> Result<String, RegistrarError> {
    // The statement must name US as the destination. It says where it is going,
    // and it is verified against a key the caller also supplies, so without
    // this a statement written for registrar B replays at C and C takes
    // custody of a handle nobody moved there.
    let self_url = normalize_registrar_url(self_url)?;
    if normalize_registrar_url(new_registrar)? != self_url {
        return Err(RegistrarError::Invalid(
            "this re-home statement names a different destination registrar".into(),
        ));
    }
    check_rehome_freshness(timestamp)?;
    verify_rehome_sig(agent_id, handle, new_registrar, timestamp, signature_b64)?;

    let agent_id = agent_id.trim();
    let handle = handle.trim().to_string();
    let key = handle.to_lowercase();
    let stmt = statement_hash(&handle, &normalize_registrar_url(new_registrar)?, timestamp, signature_b64);

    let (name, email) = split_handle(&handle, anchor)?;
    let name = name.to_string();
    // THROUGH `normalize_email`, not straight off the display handle. The string
    // here is a slice of a handle whose case the SIGNER chose, and every other
    // writer of `handles.email` stores the anchor lowercased (`claim` gets it
    // from a session, `mint_session_as` normalizes). A row written with
    // `Ann@Example.com` in that column was invisible to its own owner: `mine`
    // and `release` both compare `email = $1` with no folding, so the handle was
    // missing from the owner's roster, could not be released by them, and was
    // skipped by the account-closure enumeration in `services/` for the same
    // reason. `handle_key` is already the lowercased whole handle, so this
    // changes no identity — `Agent.ANN@x.com` and `Agent.ann@x.com` were always
    // one handle here, and the anchor a handle's own name spells out is the
    // anchor it belongs to.
    //
    // It also VALIDATES, which is a small tightening: a re-home whose anchor is
    // not a well-formed address is now a 400 instead of a row nobody can act on.
    // `claim` has always required that of an anchor; migration in had not.
    let email = normalize_email(email)?;
    // The display handle keeps the case the key signed. `handle_key` decides
    // identity and `email` now decides ownership, so the display form is
    // presentation only — and rewriting it would silently change the `handle`
    // field of a card a resolver may already have pinned bytes of (§5.3).

    // Is this name ours to take? Three ways it is not.
    // (a) somebody else already holds it here — the signature proves control
    //     of the KEY in the statement, never of a handle already bound to a
    //     different key, so accepting would be a hijack.
    let existing: Option<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT listing_id FROM handles WHERE handle_key = $1 AND released_at IS NULL",
    )
    .bind(&key)
    .fetch_optional(pool)
    .await?;
    if let Some((existing_listing,)) = existing {
        let bound_key: Option<(String,)> = match existing_listing {
            Some(id) => sqlx::query_as("SELECT source_id FROM listings WHERE id = $1")
                .bind(id)
                .fetch_optional(pool)
                .await?,
            None => None,
        };
        match bound_key.as_ref().map(|(k,)| k.trim()) {
            Some(k) if k == agent_id => {} // same key arriving again: idempotent
            _ => {
                return Err(RegistrarError::Taken(
                    "that handle is already held here by a different key".into(),
                ))
            }
        }
    }

    // (b) it is in its cooling-off window here — a name released at this
    //     registrar is not available again yet, and a move must not be a way
    //     around the wait.
    let (cooling,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM handles WHERE handle_key = $1 AND released_at > now() - ($2 || ' days')::interval",
    )
    .bind(&key)
    .bind(COOLING_OFF_DAYS.to_string())
    .fetch_one(pool)
    .await?;
    if cooling > 0 {
        return Err(RegistrarError::Taken(
            "that handle was recently released here and is in its cooling-off period".into(),
        ));
    }

    // (c) the registrar it claims to come from does not agree it left. This is
    //     the check that turns a self-signed bearer statement into custody, and
    //     it is only worth anything if the answer comes from a party we chose
    //     to peer with and is signed by that party (§5.6 check 5, §7.8).
    let corroborated = corroborate_with_old_registrar(old_registrar, &handle, &self_url).await?;

    // One transaction from here: the statement is spent, the rows are written
    // and the §6 entry appended together.
    let mut tx = pool.begin().await?;
    if !try_spend_statement(&mut tx, &stmt, &handle, agent_id, "rehome-in").await? {
        return Err(RegistrarError::Invalid(
            "this re-home statement has already been used — sign a fresh one".into(),
        ));
    }

    let (listing_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO listings (source, source_id, name, description, manifest, specialties, protocol) \
         VALUES ('agent', $1, $2, '', $3, '{}', 'mesh') \
         ON CONFLICT (source, source_id) DO UPDATE SET name = EXCLUDED.name, updated_at = now() \
         RETURNING id",
    )
    .bind(agent_id)
    .bind(&name)
    .bind(serde_json::json!({ "id": agent_id }))
    .fetch_one(&mut *tx)
    .await?;

    let via = format!("rehomed:{}", normalize_registrar_url(old_registrar)?);
    // `anchor` is NOT the anchor's address — it is the anchor TIER, 'email' or
    // 'domain' (migration 0003), and every other row in the table carries the
    // column default 'email'. This INSERT used to bind the split-out address
    // into it, which put a member's email into the one handle column that is
    // meant to hold a two-value enum and made a re-homed handle the only row in
    // the owner's roster whose `anchor` field was an address. Left unbound so
    // the default applies, the way `claim` already does it.
    sqlx::query(
        "INSERT INTO handles (handle, handle_key, email, listing_id, bind_method, claimed_via, verified_at) \
         VALUES ($1, $2, $3, $4, 'agent-key', $5, now()) \
         ON CONFLICT (handle_key) WHERE released_at IS NULL DO UPDATE SET listing_id = EXCLUDED.listing_id, \
           bind_method = 'agent-key', claimed_via = EXCLUDED.claimed_via, rehomed_to = NULL",
    )
    .bind(&handle)
    .bind(&key)
    .bind(&email)
    .bind(listing_id)
    .bind(&via)
    .execute(&mut *tx)
    .await?;

    // §5.1 marks the operator record REQUIRED on every card, and a handle that
    // arrives by migration has no claim ceremony to set one — its card went out
    // with `operator: null`. The losing registrar states the operator name in
    // the signed referral, so the label survives the move; failing that, the
    // anchor's local part stands in until the owner sets their own under a
    // verified session.
    //
    // Keyed on the SAME normalized anchor as the row above, and it has to be:
    // resolution looks the operator up by `handles.email` (`api::resolve_handle`,
    // `api::card_page`), so a handle whose two rows disagreed on case would serve
    // a card with `operator: null` — the field §5.1 marks required.
    let operator_name = corroborated.operator.unwrap_or_else(|| {
        email.split('@').next().unwrap_or("agent operator").trim().to_string()
    });
    sqlx::query(
        "INSERT INTO operators (email, display_name, updated_at) VALUES ($1, $2, now()) \
         ON CONFLICT (email) DO NOTHING",
    )
    .bind(&email)
    .bind(&operator_name)
    .execute(&mut *tx)
    .await?;

    log_action_tx(
        &mut tx,
        "rehomed-in",
        &handle,
        &email,
        serde_json::json!({ "old_registrar": old_registrar, "agent_id": agent_id, "method": "agent-key" }),
    )
    .await?;
    tx.commit().await?;
    log::info!("[pan] rehomed in: {handle} <- {old_registrar} ({agent_id})");
    Ok(handle)
}

/// Delegated binding (§4.3): a partner that has itself verified control of
/// the agent key first-hand (an equivalent signed ceremony) attests it over
/// a delegated session. No second pairing ceremony from the agent; the
/// binding record and the card disclose the witness instead.
///
/// `revoke_previous` is the owner's statement, carried by the partner, that
/// the key this binding replaces leaked and is revoked (SPEC.md §5.3). It is
/// recorded on the §4.4 key change, served on the card, and stated on the card
/// page. It changes nothing when the binding replaces no key.
pub async fn pair_delegated(
    pool: &PgPool,
    email: &str,
    partner: &str,
    handle: &str,
    agent_id: &str,
    revoke_previous: bool,
) -> Result<String, RegistrarError> {
    let agent_id = agent_id.trim();
    nkeys::KeyPair::from_public_key(agent_id)
        .map_err(|_| RegistrarError::Invalid("agent_id is not a valid public key".into()))?;

    // One transaction: the ownership check, the rebind, the §4.4 key-change
    // record and the §6 entry commit together or not at all.
    let mut tx = pool.begin().await?;
    // The session's email must anchor the handle (§4.3 scope). The same locked
    // read also captures what key the name pointed at before this binding.
    let row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT h.handle, (SELECT l.source_id FROM listings l \
                           WHERE l.id = h.listing_id AND l.source IN ('agent','agentmesh')) \
         FROM handles h \
         WHERE h.handle_key = lower($1) AND h.email = $2 AND h.released_at IS NULL FOR UPDATE OF h",
    )
    .bind(handle)
    .bind(email)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((handle, previous_key)) = row else {
        return Err(RegistrarError::Unauthorized);
    };

    let method = format!("agent-key-delegated:{partner}");
    // The session's email anchors this handle (checked just above), so the
    // name is the handle with it taken off the end (see split_handle).
    let stripped = strip_anchor(&handle, email);
    let name = stripped.as_deref().unwrap_or(handle.as_str());
    let (listing_id,): (Uuid,) = sqlx::query_as(
        "INSERT INTO listings (source, source_id, name, description, manifest, specialties, protocol) \
         VALUES ('agent', $1, $2, '', $3, '{}', 'mesh') \
         ON CONFLICT (source, source_id) DO UPDATE SET name = EXCLUDED.name, updated_at = now() \
         RETURNING id",
    )
    .bind(agent_id)
    .bind(name)
    .bind(serde_json::json!({ "id": agent_id }))
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "UPDATE handles SET listing_id = $2, bind_method = $3 \
         WHERE handle_key = lower($1) AND released_at IS NULL",
    )
    .bind(&handle)
    .bind(listing_id)
    .bind(&method)
    .execute(&mut *tx)
    .await?;
    // §4.4: a delegated binding can re-point a bound name to a new key exactly
    // as a direct pairing can, so it is recorded the same way.
    let rebound_from = previous_key.as_deref().filter(|k| *k != agent_id);
    if let Some(old) = rebound_from {
        record_key_change_tx(&mut tx, &handle.to_lowercase(), old, Some(agent_id), &method, revoke_previous)
            .await?;
    }
    let mut detail =
        serde_json::json!({ "listing_id": listing_id, "method": method, "agent_id": agent_id });
    if let Some(old) = rebound_from {
        detail["previous_agent_id"] = serde_json::Value::String(old.to_string());
        if revoke_previous {
            detail["previous_key_revoked"] = serde_json::Value::Bool(true);
        }
    }
    log_action_tx(&mut tx, "bound", &handle, email, detail).await?;
    tx.commit().await?;
    log::info!("[pan] bound: {handle} -> {listing_id} ({method}, {agent_id})");
    Ok(handle)
}

/// Release a handle (tombstone). It stays in history and cools off.
pub async fn release(pool: &PgPool, email: &str, handle: &str) -> Result<(), RegistrarError> {
    let n = sqlx::query(
        "UPDATE handles SET released_at = now() WHERE handle_key = lower($1) AND email = $2 AND released_at IS NULL",
    )
    .bind(handle)
    .bind(email)
    .execute(pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(RegistrarError::Unauthorized);
    }
    log_action(pool, "released", handle, email, serde_json::json!({})).await?;
    log::info!("[pan] released: {handle}");
    Ok(())
}

/// What a release did, so the caller can tell its user when the name frees up.
#[derive(Debug)]
pub struct Released {
    /// The handle as stored, in its original case.
    pub handle: String,
    pub released_at: DateTime<Utc>,
    /// When the cooling-off window (§3, REQUIRED minimum 90 days) expires and
    /// the name may be claimed again — by anyone, including its former owner.
    pub claimable_after: DateTime<Utc>,
}

/// Release a handle on the authority of the anchor it belongs to, recording HOW
/// that anchor was established (`via`: `email`, `delegated:<partner>`).
///
/// This is the same act as `release` — one tombstone, `released_at`, the §6 entry,
/// the cooling-off window that `claim` and `rehome_in` both read — with two
/// differences that exist for the delegated path in §3.1.
///
/// **It says why it refused.** `release` folds the ownership test into the
/// UPDATE's WHERE clause, so a handle that belongs to somebody else and a handle
/// that does not exist are the same zero rows and the same `Unauthorized`. That
/// answer is wrong for a session that has not expired, and it is the answer a
/// caller most needs to distinguish: "not yours" is a bug in the caller, "gone"
/// is a no-op it can move past. The row is read `FOR UPDATE` and the anchors are
/// compared here, in one transaction with the write, so saying which it was costs
/// no atomicity.
///
/// **The anchors are compared case-folded**, via `anchor_key`, the same
/// normalization `log_owner_tokens` uses as its primary key — so one person is
/// one anchor here too. `release`'s `email = $2` is case-SENSITIVE against a
/// column `rehome_in` fills from the display handle rather than from
/// `normalize_email`, which is a latent hole in the direct path, not something
/// this path should inherit.
///
/// The action value is `released`, the ordinary owner release, because that is
/// what happened: the owner's anchor gave up the name. §3.1's disclosure rule
/// puts the provenance in `detail.via` rather than in a second action value, the
/// way `claim` already discloses a delegated claim. `released_by_operator` stays
/// what it has always meant — the operator took a name down for cause — and a
/// user closing their own account must not be written into an append-only log as
/// that.
pub async fn release_by_anchor(
    pool: &PgPool,
    anchor: &str,
    handle: &str,
    via: &str,
) -> Result<Released, RegistrarError> {
    let key = handle.trim().to_lowercase();
    let mut tx = pool.begin().await?;
    let row: Option<(String, String)> = sqlx::query_as(
        "SELECT handle, email FROM handles WHERE handle_key = $1 AND released_at IS NULL FOR UPDATE",
    )
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((display, owner)) = row else {
        return Err(RegistrarError::Invalid(
            "no active handle by that name — it was never claimed here, or it is already released".into(),
        ));
    };
    // THE SECURITY PROPERTY OF THIS PATH. A delegated session speaks for one
    // anchor; it may give up that anchor's names and no others.
    if anchor_key(&owner) != anchor_key(anchor) {
        return Err(RegistrarError::Forbidden(
            "that handle is anchored to a different email address than this session speaks for".into(),
        ));
    }
    let (released_at,): (DateTime<Utc>,) = sqlx::query_as(
        "UPDATE handles SET released_at = now() WHERE handle_key = $1 AND released_at IS NULL \
         RETURNING released_at",
    )
    .bind(&key)
    .fetch_one(&mut *tx)
    .await?;
    // Logged against the handle's OWN anchor as stored (§6), not against the
    // string the caller sent: those differ in case for a re-homed handle, and
    // `strip_anchor` only separates the name from the anchor when they agree.
    log_action_tx(&mut tx, "released", &display, &owner, serde_json::json!({ "via": via })).await?;
    tx.commit().await?;
    log::info!("[pan] released: {display} (via {via})");
    Ok(Released {
        handle: display,
        released_at,
        claimable_after: released_at + chrono::Duration::days(COOLING_OFF_DAYS),
    })
}

/// Operator release: revoke a handle by name alone, regardless of owner — the
/// namespace-moderation lever (a partner/operator taking a name down for
/// cause). Distinct from `release`, which requires the owner's email. Logs the
/// actual owner for audit. Returns the released handle's owner email, or
/// Unauthorized when there is no active handle by that name.
pub async fn release_any(pool: &PgPool, handle: &str) -> Result<String, RegistrarError> {
    let row: Option<(String,)> = sqlx::query_as(
        "UPDATE handles SET released_at = now() WHERE handle_key = lower($1) AND released_at IS NULL RETURNING email",
    )
    .bind(handle)
    .fetch_optional(pool)
    .await?;
    let email = row.ok_or(RegistrarError::Unauthorized)?.0;
    log_action(pool, "released_by_operator", handle, &email, serde_json::json!({})).await?;
    log::info!("[pan] operator released: {handle} (was {email})");
    Ok(email)
}

/// All active handles anchored to an email.
pub async fn mine(pool: &PgPool, email: &str) -> Result<Vec<Handle>, RegistrarError> {
    Ok(sqlx::query_as::<_, Handle>(concat!(
        "SELECT ",
        handle_cols!(),
        " FROM handles WHERE email = $1 AND released_at IS NULL ORDER BY created_at"
    ))
    .bind(email)
    .fetch_all(pool)
    .await?)
}

/// Exact-string resolution: handle -> its record (active only).
pub async fn resolve(pool: &PgPool, handle: &str) -> Result<Option<Handle>, RegistrarError> {
    Ok(sqlx::query_as::<_, Handle>(concat!(
        "SELECT ",
        handle_cols!(),
        " FROM handles WHERE handle_key = lower(trim($1)) AND released_at IS NULL"
    ))
    .bind(handle)
    .fetch_optional(pool)
    .await?)
}

/// The referral obligation lookup (§5.6): a handle that re-homed away from here
/// keeps resolving to a referral, INCLUDING after the row is later released.
///
/// `resolve` filters `released_at IS NULL`, so a handle that re-homed and was
/// then released here stopped resolving at all — the obligation to point at the
/// new custodian lapsed early and, to every consumer holding the old address,
/// the name simply vanished. Returns (display handle, destination, anchor).
pub async fn resolve_rehomed(
    pool: &PgPool,
    handle: &str,
) -> Result<Option<(String, String, String)>, RegistrarError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT handle, rehomed_to, email FROM handles \
         WHERE handle_key = lower(trim($1)) AND rehomed_to IS NOT NULL \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(handle)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

// ── A rename within this registrar (§5.8) ───────────────────────────────────

/// How long an old handle keeps resolving after a rename when the caller does
/// not say, and the most it may. The cooling-off period after release (§3) is
/// separate and follows it.
pub const RENAME_WINDOW_DEFAULT_DAYS: i64 = 30;
pub const RENAME_WINDOW_MAX_DAYS: i64 = 90;

/// What a resolver is told about a renamed handle that still resolves.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RenameNotice {
    pub renamed_to: String,
    pub stops_at: String,
    pub says: String,
}

/// The notice for a handle, at a moment: Some while its rename window is
/// open, None for a handle never renamed or whose window has closed.
pub fn rename_notice(h: &Handle, now: DateTime<Utc>) -> Option<RenameNotice> {
    let to = h.renamed_to.as_ref()?;
    let until = h.renamed_until?;
    if until <= now {
        return None;
    }
    let day = until.format("%Y-%m-%d").to_string();
    Some(RenameNotice {
        renamed_to: to.clone(),
        stops_at: until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        says: format!("{} was renamed to {}. This name stops working on {}; use {}.", h.handle, to, day, to),
    })
}

/// Whether a renamed handle's window has closed, so it must not resolve even
/// though nobody has released it yet.
pub fn rename_window_closed(h: &Handle, now: DateTime<Utc>) -> bool {
    matches!((h.renamed_to.as_ref(), h.renamed_until), (Some(_), Some(until)) if until <= now)
}

/// The words a resolver gets for a renamed handle that no longer resolves,
/// with the day it stopped. The platform's notices for renamed tools and
/// commands say the same two sentences (in the window and after it); change
/// them together.
pub fn moved_words(old: &str, to: &str, stopped: DateTime<Utc>) -> String {
    let day = stopped.format("%Y-%m-%d");
    format!("{old} was renamed to {to} and stopped working on {day}. Use {to}.")
}

/// Open a rename window on `old` (§5.8), on the authority of its anchor: the
/// new handle must be active and bound to the same agent as the old one.
/// Returns when the window closes. Setting it again moves the end; it never
/// re-opens a released handle.
pub async fn set_rename_window(
    pool: &PgPool,
    anchor: &str,
    old: &str,
    to: &str,
    days: i64,
    via: &str,
) -> Result<DateTime<Utc>, RegistrarError> {
    if !(1..=RENAME_WINDOW_MAX_DAYS).contains(&days) {
        return Err(RegistrarError::Invalid(format!(
            "a rename window is 1 to {RENAME_WINDOW_MAX_DAYS} days"
        )));
    }
    let old_key = old.trim().to_lowercase();
    let to_key = to.trim().to_lowercase();
    if old_key == to_key {
        return Err(RegistrarError::Invalid("the new handle is the old one".into()));
    }
    let mut tx = pool.begin().await?;
    let old_row: Option<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT handle, email, listing_id FROM handles WHERE handle_key = $1 AND released_at IS NULL FOR UPDATE",
    )
    .bind(&old_key)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((old_display, owner, old_listing)) = old_row else {
        return Err(RegistrarError::Invalid("no active handle by the old name".into()));
    };
    if anchor_key(&owner) != anchor_key(anchor) {
        return Err(RegistrarError::Forbidden(
            "the old handle is anchored to a different email address than this session speaks for".into(),
        ));
    }
    let new_row: Option<(String, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT handle, email, listing_id FROM handles WHERE handle_key = $1 AND released_at IS NULL",
    )
    .bind(&to_key)
    .fetch_optional(&mut *tx)
    .await?;
    // The new handle may sit under another anchor (an agent moving from one of
    // its owner's anchors to another, say system@ to platform@): what makes the
    // notice true is that both names reach the same agent record.
    let Some((to_display, _to_owner, to_listing)) = new_row else {
        return Err(RegistrarError::Invalid("the new handle is not claimed here; claim and bind it first".into()));
    };
    if old_listing.is_none() || old_listing != to_listing {
        return Err(RegistrarError::Invalid(
            "the new handle is not bound to the same agent as the old one; bind it to the same key first".into(),
        ));
    }
    let (until,): (DateTime<Utc>,) = sqlx::query_as(
        "UPDATE handles SET renamed_to = $2, renamed_at = COALESCE(renamed_at, now()), \
         renamed_until = now() + ($3 || ' days')::interval \
         WHERE handle_key = $1 AND released_at IS NULL RETURNING renamed_until",
    )
    .bind(&old_key)
    .bind(&to_display)
    .bind(days.to_string())
    .fetch_one(&mut *tx)
    .await?;
    log_action_tx(
        &mut tx,
        "renamed",
        &old_display,
        &owner,
        serde_json::json!({ "to": to_display, "until": until.to_rfc3339_opts(chrono::SecondsFormat::Secs, true), "via": via }),
    )
    .await?;
    tx.commit().await?;
    log::info!("[pan] renamed: {old_display} -> {to_display} (old name works until {until}, via {via})");
    Ok(until)
}

/// A renamed handle that no longer resolves, inside the cooling-off period
/// after its release (or not yet released, past its window): (display handle,
/// the new handle, the moment it stopped: the window's end, or the release if
/// that came first). Lets resolution answer "moved to" instead of "no agent by
/// that name" (§5.8).
pub async fn resolve_moved(pool: &PgPool, handle: &str) -> Result<Option<(String, String, DateTime<Utc>)>, RegistrarError> {
    let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT handle, renamed_to, LEAST(renamed_until, COALESCE(released_at, renamed_until)) FROM handles \
         WHERE handle_key = lower(trim($1)) AND renamed_to IS NOT NULL \
           AND ((released_at IS NULL AND renamed_until <= now()) \
                OR (released_at IS NOT NULL AND released_at > now() - ($2 || ' days')::interval)) \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(handle)
    .bind(COOLING_OFF_DAYS.to_string())
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// The declared agent profile (User-Agent trust class): what kind of agent,
/// hosted by what, on which platform. Signed into the check-in canonical.
#[derive(Debug, Default, Clone, serde::Deserialize)]
pub struct AgentProfile {
    pub kind: Option<String>,
    pub host: Option<String>,
    pub platform: Option<String>,
    /// X25519 encryption public key (SPEC 4.3): lets others seal content to
    /// this agent. Public on the card; declared via the v3 canonical.
    pub encryption_key: Option<String>,
}

/// Record where an agent last connected from (owner-facing provenance) and,
/// when declared, its profile. Profile fields only overwrite when supplied;
/// first_connected_at is set once.
pub async fn record_agent_seen(
    pool: &PgPool,
    agent_id: &str,
    ip: &str,
    profile: &AgentProfile,
) -> Result<(), RegistrarError> {
    let trim = |o: &Option<String>| o.as_deref().map(str::trim).filter(|s| !s.is_empty() && s.chars().count() <= 80).map(str::to_string);
    sqlx::query(
        "UPDATE listings SET last_seen_ip = $2, last_seen_ip_at = now(), \
           first_connected_at = COALESCE(first_connected_at, now()), \
           agent_kind = COALESCE($3, agent_kind), \
           agent_host = COALESCE($4, agent_host), \
           agent_platform = COALESCE($5, agent_platform), \
           agent_encryption_key = COALESCE($6, agent_encryption_key) \
         WHERE source IN ('agent','agentmesh') AND source_id = $1",
    )
    .bind(agent_id.trim())
    .bind(ip)
    .bind(trim(&profile.kind))
    .bind(trim(&profile.host))
    .bind(trim(&profile.platform))
    .bind(trim(&profile.encryption_key))
    .execute(pool)
    .await?;
    Ok(())
}

/// Signed check-in (adapter start): proves key control, refreshes last-seen,
/// and carries the declared profile. Canonicals (newline-joined so free-text
/// fields cannot create ambiguity):
///   v1: `pan-checkin-v1:<ts>:<agent-id>`                       (no profile)
///   v2: "pan-checkin-v2"\n<ts>\n<agent-id>\n<kind>\n<host>\n<platform>
///   v3: v2 fields + \n<encryption_key>       (declares the X25519 public key)
/// The timestamp must be within a small window so a captured request cannot
/// be replayed later to plant stale data.
pub async fn checkin(
    pool: &PgPool,
    agent_id: &str,
    ts: i64,
    signature_b64: &str,
    ip: &str,
    profile: &AgentProfile,
) -> Result<(), RegistrarError> {
    use base64::Engine;
    let now = Utc::now().timestamp();
    // Checked arithmetic on a caller-supplied i64: `ts = i64::MIN + now` wraps
    // twice under a release profile with overflow checks off, and a wrapped
    // difference lands inside the window.
    match now.checked_sub(ts).and_then(i64::checked_abs) {
        Some(delta) if delta <= 300 => {}
        _ => {
            return Err(RegistrarError::Invalid(
                "check-in timestamp outside the accepted window".into(),
            ))
        }
    }
    let sig = base64::engine::general_purpose::STANDARD
        .decode(signature_b64.trim())
        .map_err(|_| RegistrarError::Invalid("signature is not valid base64".into()))?;
    let agent_id = agent_id.trim();
    let has_profile = profile.kind.is_some() || profile.host.is_some() || profile.platform.is_some();
    let msg = if profile.encryption_key.is_some() {
        [
            "pan-checkin-v3".to_string(),
            ts.to_string(),
            agent_id.to_string(),
            profile.kind.clone().unwrap_or_default(),
            profile.host.clone().unwrap_or_default(),
            profile.platform.clone().unwrap_or_default(),
            profile.encryption_key.clone().unwrap_or_default(),
        ]
        .join("\n")
    } else if has_profile {
        [
            "pan-checkin-v2".to_string(),
            ts.to_string(),
            agent_id.to_string(),
            profile.kind.clone().unwrap_or_default(),
            profile.host.clone().unwrap_or_default(),
            profile.platform.clone().unwrap_or_default(),
        ]
        .join("\n")
    } else {
        format!("pan-checkin-v1:{ts}:{agent_id}")
    };
    let kp = nkeys::KeyPair::from_public_key(agent_id)
        .map_err(|_| RegistrarError::Invalid("agent_id is not a valid public key".into()))?;
    kp.verify(msg.as_bytes(), &sig)
        .map_err(|_| RegistrarError::Invalid("signature does not verify against the agent key".into()))?;
    record_agent_seen(pool, agent_id, ip, profile).await
}

/// Owner-only: provenance + declared profile for a set of listings.
pub type SeenRow = (Option<String>, Option<DateTime<Utc>>, Option<String>, Option<String>, Option<String>, Option<DateTime<Utc>>, Option<String>);
pub async fn last_seen_ips(
    pool: &PgPool,
    listing_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, SeenRow>, RegistrarError> {
    let rows: Vec<(Uuid, Option<String>, Option<DateTime<Utc>>, Option<String>, Option<String>, Option<String>, Option<DateTime<Utc>>, Option<String>)> = sqlx::query_as(
        "SELECT id, last_seen_ip, last_seen_ip_at, agent_kind, agent_host, agent_platform, first_connected_at, agent_encryption_key          FROM listings WHERE id = ANY($1)",
    )
    .bind(listing_ids)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(id, ip, at, k, h, pf, fc, ek)| (id, (ip, at, k, h, pf, fc, ek))).collect())
}

/// Reverse resolution (PAN v0.3): agent key -> its bound handle, if any.
/// The key is public (it arrives on every signed envelope), so this maps a
/// verified sender to a name without exposing anything a card does not.
pub async fn resolve_by_agent(pool: &PgPool, agent_id: &str) -> Result<Option<Handle>, RegistrarError> {
    Ok(sqlx::query_as::<_, Handle>(concat!(
        "SELECT ",
        handle_cols!(),
        " FROM handles WHERE released_at IS NULL AND listing_id IN \
          (SELECT id FROM listings WHERE source IN ('agent','agentmesh') AND source_id = $1) \
          ORDER BY (renamed_to IS NOT NULL), created_at DESC LIMIT 1"
    ))
    .bind(agent_id.trim())
    .fetch_optional(pool)
    .await?)
}

/// The operator's display name (PAN v0.3): one required public label per
/// verified email, shown on every card of that owner's handles. It is the
/// operator's CHOSEN label anchored to the proven email; it is not verified
/// identity, and the spec says so.
pub async fn operator_get(pool: &PgPool, email: &str) -> Result<Option<String>, RegistrarError> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT display_name FROM operators WHERE email = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0))
}

pub async fn operator_discoverable_get(pool: &PgPool, email: &str) -> Result<bool, RegistrarError> {
    let row: Option<(bool,)> =
        sqlx::query_as("SELECT discoverable FROM operators WHERE email = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|r| r.0).unwrap_or(false))
}

/// Flip the §5.4 discoverability consent. Requires an operator record (a
/// display name) to exist — you become findable as someone, not as a blank.
pub async fn operator_discoverable_set(
    pool: &PgPool,
    email: &str,
    discoverable: bool,
) -> Result<(), RegistrarError> {
    let n = sqlx::query("UPDATE operators SET discoverable = $2, updated_at = now() WHERE email = $1")
        .bind(email)
        .bind(discoverable)
        .execute(pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(RegistrarError::Invalid("set an operator display name first".into()));
    }
    log_action(pool, "discoverable", "-", email, serde_json::json!({ "discoverable": discoverable })).await?;
    log::info!("[pan] discoverable={discoverable} for {email}");
    Ok(())
}

/// §5.4 discovery: the consented exception to no-enumeration. Returns the
/// anchor's active handles ONLY when its owner opted in; otherwise reports
/// not-discoverable — indistinguishable from "no agents", by design.
pub async fn discover_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<Vec<Handle>>, RegistrarError> {
    let email = email.trim().to_lowercase();
    if !operator_discoverable_get(pool, &email).await? {
        return Ok(None);
    }
    Ok(Some(mine(pool, &email).await?))
}

/// Validate an operator display name without writing anything. Split out so a
/// claim can reject a bad name BEFORE it touches the operator record: setting
/// the name first meant a claim that then failed (taken, cooling off, re-homed)
/// still renamed the operator.
pub fn validate_operator_name(display_name: &str) -> Result<String, RegistrarError> {
    let name = display_name.trim();
    if name.is_empty() || name.chars().count() > 80 {
        return Err(RegistrarError::Invalid(
            "operator display name must be 1-80 characters".into(),
        ));
    }
    Ok(name.to_string())
}

/// Set or update the operator display name (logged, like every registrar action).
pub async fn operator_set(
    pool: &PgPool,
    email: &str,
    display_name: &str,
) -> Result<String, RegistrarError> {
    let name = validate_operator_name(display_name)?;
    let name = name.as_str();
    sqlx::query(
        "INSERT INTO operators (email, display_name, updated_at) VALUES ($1, $2, now()) \
         ON CONFLICT (email) DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = now()",
    )
    .bind(email)
    .bind(name)
    .execute(pool)
    .await?;
    log_action(pool, "operator", "-", email, serde_json::json!({ "display_name": name })).await?;
    log::info!("[pan] operator name set for {email}");
    Ok(name.to_string())
}

/// One `handle_log` row as a verifier needs it: both owner shapes, so a walk of
/// the chain does not have to care which side of the 0013 cutover a row is on.
//
// This crate has only a bin target, so `pub` is reachability within the crate,
// not an external export, and anything no route calls yet reads as dead. The
// verifier and the erasure below are deliberately unwired (the deletion plan
// says add the mechanism, not the request flow), so they are marked rather than
// left to warn on every build.
#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LogRow {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub action: String,
    pub detail: serde_json::Value,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
    /// Pre-cutover only: plaintext anchor, whole handle.
    pub email: Option<String>,
    pub handle: Option<String>,
    /// Post-cutover only: opaque token, anchor-free name.
    pub owner_token: Option<String>,
    pub handle_name: Option<String>,
}

#[allow(dead_code)]
impl LogRow {
    /// Which canonicalization rule this row's hash was computed under. The row's
    /// own shape is the discriminator — `owner_token` set means post-cutover —
    /// and the `handle_log_owner_shape` CHECK is what makes that unambiguous.
    pub fn owner(&self) -> Option<LogOwner<'_>> {
        match (&self.owner_token, &self.email, &self.handle) {
            (Some(t), _, _) => {
                Some(LogOwner::Token { handle_name: self.handle_name.as_deref(), owner_token: t })
            }
            (None, Some(e), Some(h)) => Some(LogOwner::Anchor { handle: h, email: e }),
            _ => None,
        }
    }

    /// Recompute this row's hash from its stored fields. None for a row that has
    /// no owner shape at all, which the CHECK constraint forbids.
    pub fn recompute_hash(&self) -> Option<String> {
        let owner = self.owner()?;
        Some(log_entry_hash(
            self.id,
            &self.at,
            &self.action,
            &self.detail,
            self.prev_hash.as_deref().unwrap_or_default(),
            owner,
        ))
    }
}

/// Walk a run of log rows (ascending by id) and check that each one's stored
/// hash is the hash of its own contents, and that each links to the one before.
/// Returns how many chained rows were checked.
///
/// Rows predating migration 0003 carry NULL hashes and are skipped: the chain
/// geneses at the first row that has one. Rows on either side of the 0013
/// cutover are checked under their own rule, so the chain verifies END TO END
/// across it — and it keeps verifying after a `forget_anchor`, because nothing
/// the hash covers lives in the mapping that erasure deletes.
#[allow(dead_code)]
pub fn verify_log_chain(rows: &[LogRow]) -> Result<usize, String> {
    let mut checked = 0usize;
    let mut expect_prev: Option<String> = None;
    for row in rows {
        let Some(stored) = row.entry_hash.as_deref() else {
            if row.prev_hash.is_some() {
                return Err(format!("row {} has a prev_hash but no entry_hash", row.id));
            }
            continue; // pre-0003 row, outside the chain
        };
        let prev = row.prev_hash.as_deref().unwrap_or_default();
        if let Some(want) = &expect_prev {
            if prev != want {
                return Err(format!(
                    "row {} breaks the chain: prev_hash {prev:?} does not match the previous entry_hash {want:?}",
                    row.id
                ));
            }
        }
        let recomputed = row
            .recompute_hash()
            .ok_or_else(|| format!("row {} carries no owner (neither email nor owner_token)", row.id))?;
        if recomputed != stored {
            return Err(format!("row {} does not hash to its stored entry_hash", row.id));
        }
        expect_prev = Some(stored.to_string());
        checked += 1;
    }
    Ok(checked)
}

// ---------------------------------------------------------------------------
// Signed head commitments (§6)
// ---------------------------------------------------------------------------
//
// `verify_log_chain` above proves a run of rows is internally consistent. It
// cannot prove the run is the WHOLE run, and an owner only ever receives their
// own sparse subset of it, so for them it cannot even prove that much. A chain
// that was deleted and restarted verifies exactly as well as one that was not:
// the genesis is the empty string, so a shorter chain is still a valid chain.
//
// A commitment is the registrar signing, publicly and periodically, where its
// chain ends and how long it is. It converts "trust that nothing was removed"
// into "removing something contradicts a signature you already published".

/// Where the chain currently ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogHead {
    /// Id of the newest row that carries a hash.
    pub seq: i64,
    pub hash: String,
    /// How many rows carry a hash. The count is the part truncation cannot
    /// hide — a hash proves a row is intact, a count proves rows are present.
    pub entries: i64,
}

/// The exact bytes a head commitment covers.
///
/// Newline-joined and version-tagged, like the other signed statements here
/// (`pan-rehome-v1`, `pan-checkin-v3`), so a verifier reconstructs them from the
/// published fields without a JSON canonicalizer.
///
/// `registrar` is inside the signature deliberately. A commitment is a claim
/// about ONE registrar's chain; without its own URL in the bytes, a commitment
/// published by A verifies as a statement about B's chain to anyone who fetched
/// it from B — the same replay the §5.6 referral fix had to close.
pub fn log_commitment_canonical(
    registrar: &str,
    head: &LogHead,
    at: &DateTime<Utc>,
) -> String {
    [
        "pan-log-commitment-v1",
        registrar.trim_end_matches('/'),
        &head.seq.to_string(),
        &head.entries.to_string(),
        &head.hash,
        &at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    ]
    .join("\n")
}

/// The current head, or None when nothing has been chained yet (a fresh
/// registrar, or one whose rows all predate migration 0003).
pub async fn current_log_head(pool: &PgPool) -> Result<Option<LogHead>, RegistrarError> {
    // One statement, so the count and the head cannot come from different
    // moments: a commitment naming a head that a concurrent append had already
    // moved past would attest to something that was never true.
    let row: Option<(i64, String, i64)> = sqlx::query_as(
        "SELECT id, entry_hash, (SELECT count(*) FROM handle_log WHERE entry_hash IS NOT NULL) \
         FROM handle_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(seq, hash, entries)| LogHead { seq, hash, entries }))
}

/// Serialize `at` at SECOND precision, which is the precision the signature
/// covers.
///
/// This is not cosmetic. `log_commitment_canonical` writes the timestamp with
/// `SecondsFormat::Secs`, while Postgres stores microseconds and chrono's default
/// serializer prints them — so the published JSON carried
/// `…T13:43:03.143751Z` for bytes that were signed over `…T13:43:03Z`. A third
/// party doing exactly what the endpoint's `canonical` hint tells them to do
/// rebuilt the wrong bytes and concluded a perfectly good signature was invalid.
/// For a mechanism whose entire purpose is verification by strangers, that made
/// the feature worse than absent: it published evidence that reads as forged.
///
/// Applied on the way OUT rather than only on the way in, so rows written before
/// the fix (whose signatures are over the truncated form) also verify.
fn at_to_signed_precision<S: serde::Serializer>(
    at: &DateTime<Utc>,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

/// A commitment as published.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct LogCommitment {
    pub id: i64,
    #[serde(serialize_with = "at_to_signed_precision")]
    pub at: DateTime<Utc>,
    pub registrar: String,
    pub head_seq: i64,
    pub head_hash: String,
    pub entries: i64,
    pub kid: String,
    pub signature: String,
}

/// Record a signed commitment. The signature is produced by the caller, because
/// the card key lives in the API layer; this module owns the chain, not the key.
pub async fn record_log_commitment(
    pool: &PgPool,
    registrar: &str,
    head: &LogHead,
    at: &DateTime<Utc>,
    kid: &str,
    signature: &str,
) -> Result<LogCommitment, RegistrarError> {
    Ok(sqlx::query_as::<_, LogCommitment>(
        "INSERT INTO log_commitments (at, registrar, head_seq, head_hash, entries, kid, signature) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         RETURNING id, at, registrar, head_seq, head_hash, entries, kid, signature",
    )
    .bind(at)
    .bind(registrar.trim_end_matches('/'))
    .bind(head.seq)
    .bind(&head.hash)
    .bind(head.entries)
    .bind(kid)
    .bind(signature)
    .fetch_one(pool)
    .await?)
}

/// The newest commitment, if any.
pub async fn latest_log_commitment(pool: &PgPool) -> Result<Option<LogCommitment>, RegistrarError> {
    Ok(sqlx::query_as::<_, LogCommitment>(
        "SELECT id, at, registrar, head_seq, head_hash, entries, kid, signature \
         FROM log_commitments ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?)
}

/// Commitments after `since`, oldest first — the shape an archiver polls with.
pub async fn list_log_commitments(
    pool: &PgPool,
    since: i64,
    limit: i64,
) -> Result<Vec<LogCommitment>, RegistrarError> {
    Ok(sqlx::query_as::<_, LogCommitment>(
        "SELECT id, at, registrar, head_seq, head_hash, entries, kid, signature \
         FROM log_commitments WHERE id > $1 ORDER BY id ASC LIMIT $2",
    )
    .bind(since)
    .bind(limit.clamp(1, 1_000))
    .fetch_all(pool)
    .await?)
}

/// Whether a new commitment is due: nothing published yet, the chain has grown,
/// or enough time has passed that a reader polling for evidence of liveness
/// should have seen one.
///
/// The time arm matters as much as the growth arm. A registrar that stops
/// issuing commitments is indistinguishable from one that has nothing to
/// report, so the cadence is what makes silence itself legible.
pub fn commitment_due(latest: Option<&LogCommitment>, head: &LogHead, now: &DateTime<Utc>, every_secs: i64) -> bool {
    match latest {
        None => true,
        Some(c) => c.entries != head.entries || (*now - c.at).num_seconds() >= every_secs,
    }
}

macro_rules! log_row_cols {
    () => {
        "id, at, action, detail, prev_hash, entry_hash, email, handle, owner_token, handle_name"
    };
}

/// A run of log rows in chain order, for [`verify_log_chain`]. Not owner-scoped
/// and not routable: this is the whole-log read an operator verification pass
/// needs, and it returns tokens, never addresses.
#[allow(dead_code)]
pub async fn log_rows(pool: &PgPool, after_seq: i64, limit: i64) -> Result<Vec<LogRow>, RegistrarError> {
    Ok(sqlx::query_as::<_, LogRow>(concat!(
        "SELECT ",
        log_row_cols!(),
        " FROM handle_log WHERE id > $1 ORDER BY id ASC LIMIT $2"
    ))
    .bind(after_seq)
    .bind(limit.clamp(1, 10_000))
    .fetch_all(pool)
    .await?)
}

/// One owner's own handle history (PAN §6). Owner-scoped by verified
/// anchor: the log is never world-readable, since email-tier handles embed
/// the owner's address and a public log would enumerate their whole roster.
///
/// Matches both shapes: pre-cutover rows by their plaintext `email`, post-cutover
/// rows by this anchor's token. An anchor whose mapping has been shredded
/// (`forget_anchor`) has no token, so its post-cutover rows are not returned here
/// or anywhere else keyed on a person — that is the erasure working, not a bug.
pub async fn log_entries(pool: &PgPool, email: &str, limit: i64) -> Result<Vec<serde_json::Value>, RegistrarError> {
    let key = anchor_key(email);
    let token: Option<String> =
        sqlx::query_scalar("SELECT token FROM log_owner_tokens WHERE email = $1")
            .bind(&key)
            .fetch_optional(pool)
            .await?;
    let rows: Vec<LogRow> = sqlx::query_as(concat!(
        "SELECT ",
        log_row_cols!(),
        " FROM handle_log WHERE email = $1 OR ($2::text IS NOT NULL AND owner_token = $2) \
          ORDER BY id DESC LIMIT $3"
    ))
    .bind(email)
    .bind(&token)
    .bind(limit.clamp(1, 500))
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| {
            // The wire shape is unchanged: `handle` and `email` are still what an
            // owner sees. For a post-cutover row they are reassembled from the
            // anchor-free name plus the anchor this very request proved control
            // of, which is why the row itself never needed to store either.
            let handle = match (&r.handle, &r.handle_name) {
                (Some(h), _) => h.clone(),
                (None, Some(n)) => format!("{n}.{email}"),
                (None, None) => "-".to_string(),
            };
            serde_json::json!({
                "seq": r.id,
                "at": r.at.to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                "action": r.action,
                "handle": handle,
                "email": r.email.clone().unwrap_or_else(|| email.to_string()),
                "detail": r.detail,
                "prev_hash": r.prev_hash,
                "entry_hash": r.entry_hash,
            })
        })
        .collect())
}

/// What a shred actually accomplished, and what it did not. Returned rather than
/// logged so the caller can be honest to the person who asked: a bare "done"
/// over an erasure that left plaintext behind is the failure mode this struct
/// exists to prevent.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub struct ForgetOutcome {
    /// Was there a mapping to delete? False means nothing was linked to begin
    /// with — either already shredded, or this anchor never appeared in the log.
    pub mapping_deleted: bool,
    /// Post-cutover log rows that just became unlinkable to a person.
    pub rows_unlinked: i64,
    /// Pre-cutover rows still carrying this address in plaintext. THESE ARE NOT
    /// ERASED and cannot be: they are hash-chained under a rule that covers the
    /// email itself, and migration 0013 records why rewriting them was refused.
    /// A non-zero count here must be disclosed, not rounded to zero.
    pub rows_still_plaintext: i64,
    /// Live (un-released) handles still anchored to this address. Each one holds
    /// the address in `handles.email` AND spells it out in its own name, so a
    /// shred performed while any of these exist buys almost nothing. A caller
    /// should release them first.
    pub live_handles: i64,
}

/// ERASURE. Delete an anchor's token-to-email mapping, so every post-cutover
/// `handle_log` row written under it becomes an opaque token belonging to nobody.
///
/// This is the crypto-shredding half of migration 0013. It deletes from
/// `log_owner_tokens` and from nothing else: no log row is touched, no hashed
/// byte changes, and `verify_log_chain` passes exactly as it did before. The
/// token stays in the log forever; what is destroyed is the only record of whose
/// it was.
///
/// SCOPE, stated so no caller can mistake this for "the user is forgotten". It
/// erases the LOG LINKAGE only. Not erased, and still plaintext after this
/// returns: the `handles` rows (including released tombstones), the `operators`
/// display name, `email_codes`, `email_sessions`, `listings.owner_email`, any
/// pre-cutover log row, and the address inside every live handle's own name. A
/// real account erasure calls this as one step among several. `ForgetOutcome`
/// reports the residue so the caller can say what is left.
///
/// IRREVERSIBLE, and deliberately not logged to `handle_log`: an entry recording
/// "this anchor asked to be forgotten" would either name the address it just
/// erased or be filed under a token that no longer resolves. Nothing about the
/// erasure is written where the erasure cannot reach.
///
/// Not wired to any route. Whoever builds the request flow decides the
/// authorization; the obvious gate is the same verified anchor session §6 uses
/// for the owner-scoped read, since anything weaker lets one person shred
/// another's history.
#[allow(dead_code)]
pub async fn forget_anchor(pool: &PgPool, email: &str) -> Result<ForgetOutcome, RegistrarError> {
    let key = anchor_key(email);
    let mut tx = pool.begin().await?;

    // The same lock every append takes, for the same reason. Without it an append
    // already inside `log_action_tx` can mint a fresh mapping for this anchor
    // moments after the delete, so the shred silently misses the entry being
    // written and `rows_unlinked` under-reports. Appends are rare and short; a
    // shred can wait for one.
    sqlx::query("SELECT pg_advisory_xact_lock(4207)").execute(&mut *tx).await?;

    let token: Option<String> = sqlx::query_scalar(
        "DELETE FROM log_owner_tokens WHERE email = $1 RETURNING token",
    )
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;

    let rows_unlinked: i64 = match &token {
        Some(t) => sqlx::query_scalar("SELECT count(*) FROM handle_log WHERE owner_token = $1")
            .bind(t)
            .fetch_one(&mut *tx)
            .await?,
        None => 0,
    };
    // Matched case-insensitively: pre-cutover rows were written with whatever
    // casing the caller passed, and an undercount here would understate the
    // residue we are obliged to disclose.
    let rows_still_plaintext: i64 =
        sqlx::query_scalar("SELECT count(*) FROM handle_log WHERE lower(email) = $1")
            .bind(&key)
            .fetch_one(&mut *tx)
            .await?;
    let live_handles: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM handles WHERE lower(email) = $1 AND released_at IS NULL",
    )
    .bind(&key)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;

    // Counts only. The address must not be echoed into the service log, which
    // has its own retention and is not covered by this erasure; and the token
    // must not either, since printing it alongside the request that named the
    // email would recreate the mapping in the log stream.
    log::info!(
        "[pan] log linkage shredded: mapping_deleted={} rows_unlinked={rows_unlinked} \
         rows_still_plaintext={rows_still_plaintext} live_handles={live_handles}",
        token.is_some()
    );
    Ok(ForgetOutcome {
        mapping_deleted: token.is_some(),
        rows_unlinked,
        rows_still_plaintext,
        live_handles,
    })
}

/// Wire-format conformance against `conformance/naming.json`.
///
/// **This module was named by the fixture before it existed.** The fixture's
/// comment has always said the Rust side asserts it too, and only the
/// JavaScript half was ever true: the side that READS cards was pinned to
/// these bytes, and the side that MINTS AND SIGNS them was pinned to nothing.
///
/// That is the wrong half to leave unguarded. A drift in the reader breaks
/// verification loudly, in the reader's own tests. A drift here is silent: the
/// registrar keeps signing, every card it issues verifies nowhere, and nobody
/// finds out until pairing or resolution fails in the field, on somebody
/// else's machine, against a signature that looks perfectly well formed.
///
/// THE FIXTURE IS THE AUTHORITY. When a case here fails, fix the registrar,
/// never the JSON. Cards already issued were signed over exactly these bytes,
/// so editing the fixture to match new behaviour would not repair a drift — it
/// would ratify it and strand every card already in the wild.
///
/// Lives inside this file rather than in `tests/` because the crate has no
/// library target: an integration test cannot reach `canonical_json`, and
/// adding a `lib.rs` to a binary crate to make one possible is a larger change
/// than the assertions are worth. Kept beside the code it pins.
#[cfg(test)]
mod naming_conformance {
    use super::*;
    use serde_json::Value;

    static FIXTURE_JSON: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/naming.json"));

    fn fixture() -> Value {
        serde_json::from_str(FIXTURE_JSON).expect("conformance/naming.json parses")
    }

    /// `pan-pair-v1:<code>:<agent-id>`, the proof of agent control.
    ///
    /// Trimmed and upper-cased on the code because a person reads it off a
    /// screen and types it back with whatever case and spacing they like. The
    /// bytes signed must not depend on that.
    #[test]
    fn pair_canonical() {
        let f = fixture();
        let code = f["pair"]["code"].as_str().expect("code");
        let agent_id = f["pair"]["agent_id"].as_str().expect("agent_id");
        assert_eq!(
            format!("pan-pair-v1:{}:{}", code.trim().to_uppercase(), agent_id),
            f["pair"]["canonical"].as_str().expect("canonical"),
        );
    }

    /// The v3 check-in: seven fields, newline-joined, in a fixed order.
    ///
    /// Absent optional profile fields are the EMPTY STRING, never omitted. The
    /// separator count is part of the message, so dropping a field shifts every
    /// field after it and produces a different signature over the same facts.
    #[test]
    fn checkin_v3_canonical() {
        let f = fixture();
        let c = &f["checkin_v3"];
        let s = |k: &str| c[k].as_str().unwrap_or("").to_string();
        let built = [
            "pan-checkin-v3".to_string(),
            c["ts"].as_i64().expect("ts").to_string(),
            s("agent_id"),
            s("kind"),
            s("host"),
            s("platform"),
            s("encryption_key"),
        ]
        .join("\n");
        assert_eq!(built, c["canonical"].as_str().expect("canonical"));
    }

    /// The canonical JSON a card signature covers.
    ///
    /// The vector is chosen to hurt: a non-ASCII operator name, nested
    /// objects, an array whose elements have their own out-of-order keys, and
    /// numbers beside strings. Those are the places two canonicalizers drift —
    /// key order at depth, escaping, and whether array order is preserved (it
    /// must be; only object keys sort).
    #[test]
    fn card_canonical_json() {
        let f = fixture();
        assert_eq!(
            canonical_json(&f["card"]["value"]),
            f["card"]["canonical"].as_str().expect("canonical"),
        );
    }

    /// Non-ASCII survives as itself.
    ///
    /// Guards "canonical" being read as "ASCII-safe". A canonicalizer that
    /// escaped non-ASCII to \u sequences would still be stable, sorted and
    /// compact, and would disagree with the JavaScript side on every card
    /// carrying a name like the fixture's.
    #[test]
    fn canonicalization_does_not_escape_non_ascii() {
        let f = fixture();
        let canonical = canonical_json(&f["card"]["value"]);
        assert!(canonical.contains("Chloë"), "diaeresis escaped or lost: {canonical}");
        assert!(canonical.contains('✓'), "check mark escaped or lost: {canonical}");
    }

    /// RFC 8785 §3.2.3: keys sort by UTF-16 code units. Byte order agrees with
    /// it everywhere except between characters above U+FFFF (a surrogate pair,
    /// starting 0xD8xx) and those from U+E000 to U+FFFF, where UTF-16 puts the
    /// surrogate pair first and UTF-8 puts it last.
    #[test]
    fn keys_sort_by_utf16_code_units() {
        let v = serde_json::json!({ "\u{FB33}": 3, "😀": 2, "é": 1, "z": 0 });
        assert_eq!(canonical_json(&v), "{\"z\":0,\"é\":1,\"😀\":2,\"\u{FB33}\":3}");
    }

    /// RFC 8785 §3.2.2.3: numbers in their ECMAScript form, and integers as
    /// they always were.
    #[test]
    fn numbers_take_their_ecmascript_form() {
        let v = serde_json::json!([1.0, 0.1, 1e21, 1e-7, -0.5, 42, -7, 18446744073709551615u64]);
        assert_eq!(canonical_json(&v), "[1,0.1,1e+21,1e-7,-0.5,42,-7,18446744073709551615]");
    }

    /// RFC 8785 appendix B's string example: the minimal escapes, lowercase hex.
    #[test]
    fn strings_take_the_minimal_escapes() {
        let v = serde_json::json!({ "s": "\u{20ac}$\u{000F}\u{000a}A'B\"\\\\\"/" });
        assert_eq!(canonical_json(&v), "{\"s\":\"€$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}");
    }
}

// The §6 chain, and the claim migration 0013 rests on: shredding an owner's
// mapping leaves the chain verifying. These tests need no database, on purpose —
// the chain is a function of the stored row fields and nothing else, and that is
// exactly the property being asserted.
#[cfg(test)]
mod head_commitments {
    use super::*;
    use chrono::TimeZone;

    fn at(n: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_784_000_000 + n, 0).single().expect("valid timestamp")
    }

    fn head(seq: i64, entries: i64) -> LogHead {
        LogHead { seq, hash: "aGVhZC1oYXNo".into(), entries }
    }

    fn commitment(entries: i64, when: DateTime<Utc>) -> LogCommitment {
        LogCommitment {
            id: 1,
            at: when,
            registrar: "https://naming.example".into(),
            head_seq: 10,
            head_hash: "aGVhZC1oYXNo".into(),
            entries,
            kid: "93acdb980800".into(),
            signature: "c2ln".into(),
        }
    }

    /// The signed bytes are a wire format: a verifier rebuilds them from the
    /// published JSON fields, so changing this shape silently invalidates every
    /// commitment anyone archived. Frozen here on purpose.
    #[test]
    fn canonical_is_frozen() {
        assert_eq!(
            log_commitment_canonical("https://naming.example", &head(4207, 12_000), &at(0)),
            "pan-log-commitment-v1\n\
             https://naming.example\n\
             4207\n\
             12000\n\
             aGVhZC1oYXNo\n\
             2026-07-14T03:33:20Z",
        );
    }

    /// A trailing slash is not a different registrar. Without normalizing it,
    /// the same deployment signs two shapes depending on how PAN_SELF_URL was
    /// typed, and a verifier reconstructing from the published `registrar`
    /// field gets a mismatch it cannot explain.
    #[test]
    fn the_registrar_url_is_normalized_before_signing() {
        assert_eq!(
            log_commitment_canonical("https://naming.example/", &head(1, 1), &at(0)),
            log_commitment_canonical("https://naming.example", &head(1, 1), &at(0)),
        );
    }

    /// THE PROPERTY THE WHOLE MECHANISM EXISTS FOR. A commitment names a chain
    /// of a given length; a chain that later reports fewer entries contradicts
    /// it. The bytes differ, so the old signature cannot be made to cover the
    /// new state.
    #[test]
    fn a_truncated_chain_cannot_match_a_commitment_it_already_published() {
        let before = log_commitment_canonical("https://r.example", &head(4207, 12_000), &at(0));
        let after_truncation = log_commitment_canonical("https://r.example", &head(4207, 400), &at(0));
        assert_ne!(before, after_truncation, "entry count must be inside the signature");
    }

    /// A commitment published by one registrar must not read as a statement
    /// about another's chain — the §5.6 referral replay, in a different costume.
    #[test]
    fn a_commitment_does_not_verify_as_another_registrars() {
        assert_ne!(
            log_commitment_canonical("https://a.example", &head(9, 9), &at(0)),
            log_commitment_canonical("https://b.example", &head(9, 9), &at(0)),
        );
    }

    /// THE PUBLISHED FORM MUST BE THE SIGNED FORM.
    ///
    /// Caught in production on 2026-08-01: Postgres stores microseconds and
    /// chrono printed them, so the endpoint served `…T13:43:03.143751Z` for a
    /// signature taken over `…T13:43:03Z`. Every field a verifier needs must
    /// round-trip out of the JSON into the canonical bytes unchanged — an
    /// endpoint whose own output cannot reproduce its own signature is worse
    /// than one that publishes nothing, because it looks like forgery.
    #[test]
    fn the_published_timestamp_reconstructs_the_signed_bytes() {
        let microseconds = Utc.timestamp_opt(1_784_000_000, 143_751_000).single().unwrap();
        let c = LogCommitment {
            id: 1,
            at: microseconds,
            registrar: "https://r.example".into(),
            head_seq: 81,
            head_hash: "aGVhZC1oYXNo".into(),
            entries: 81,
            kid: "kid1".into(),
            signature: "c2ln".into(),
        };
        let published: serde_json::Value = serde_json::to_value(&c).unwrap();
        let at_field = published["at"].as_str().expect("at serializes as a string");

        // Rebuild the canonical bytes the way a stranger with only the JSON must.
        let rebuilt = [
            "pan-log-commitment-v1",
            c.registrar.as_str(),
            &c.head_seq.to_string(),
            &c.entries.to_string(),
            c.head_hash.as_str(),
            at_field,
        ]
        .join("\n");

        let signed = log_commitment_canonical(
            &c.registrar,
            &LogHead { seq: c.head_seq, hash: c.head_hash.clone(), entries: c.entries },
            &microseconds,
        );
        assert_eq!(rebuilt, signed, "published fields must rebuild the signed bytes exactly");
        assert!(!at_field.contains('.'), "published `at` must not carry subseconds the signature excludes");
    }

    #[test]
    fn the_first_commitment_is_always_due() {
        assert!(commitment_due(None, &head(1, 1), &at(0), 3600));
    }

    #[test]
    fn growth_is_due_immediately_and_an_idle_chain_waits_for_the_cadence() {
        let last = commitment(12_000, at(0));
        // The chain grew: commit now, so the gap between a change and the
        // evidence of it is not a whole cadence long.
        assert!(commitment_due(Some(&last), &head(4208, 12_001), &at(60), 3600));
        // Nothing changed and the cadence has not elapsed: nothing to say.
        assert!(!commitment_due(Some(&last), &head(4207, 12_000), &at(60), 3600));
        // Nothing changed but the cadence elapsed: say so anyway. Silence and
        // "no news" must not look the same to a reader polling for liveness.
        assert!(commitment_due(Some(&last), &head(4207, 12_000), &at(3600), 3600));
    }

    /// Shrinkage is a change like any other, and must trigger a commitment
    /// rather than being read as "no growth, nothing to report". A registrar
    /// that truncated should publish the contradiction, not sit on it.
    #[test]
    fn a_chain_that_shrank_is_also_due() {
        let last = commitment(12_000, at(0));
        assert!(commitment_due(Some(&last), &head(400, 400), &at(60), 3600));
    }
}

#[cfg(test)]
mod head_commitments_db {
    use super::test_db::{enabled, fresh_db};
    use super::*;

    /// The head reflects the real chain, a commitment records it, and the
    /// database refuses to let that commitment be edited or removed afterwards.
    /// A commitment that can be rewritten is not evidence of anything.
    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn a_commitment_records_the_head_and_cannot_be_altered() {
        if !enabled("a_commitment_records_the_head_and_cannot_be_altered") {
            return;
        }
        let (_pg, pool) = fresh_db().await;

        // Nothing chained yet: there is no head to attest to, and that is not an
        // error — a fresh registrar has nothing to say.
        assert!(current_log_head(&pool).await.unwrap().is_none(), "empty chain has no head");

        for i in 0..3 {
            log_action(&pool, "claimed", &format!("a{i}.ann@gmail.com"), "ann@gmail.com", serde_json::json!({}))
                .await
                .unwrap();
        }
        let head = current_log_head(&pool).await.unwrap().expect("a head after appends");
        assert_eq!(head.entries, 3, "three chained rows");

        let at = Utc::now();
        let written = record_log_commitment(&pool, "https://r.example/", &head, &at, "kid1", "c2ln")
            .await
            .unwrap();
        assert_eq!(written.entries, 3);
        assert_eq!(written.head_seq, head.seq);
        assert_eq!(written.registrar, "https://r.example", "trailing slash normalized on the way in");

        // Appending moves the head; the published commitment still describes the
        // moment it was made, which is what makes a LATER contradiction visible.
        log_action(&pool, "released", "a0.ann@gmail.com", "ann@gmail.com", serde_json::json!({}))
            .await
            .unwrap();
        let grown = current_log_head(&pool).await.unwrap().unwrap();
        assert_eq!(grown.entries, 4);
        assert_eq!(latest_log_commitment(&pool).await.unwrap().unwrap().entries, 3);

        // Append-only, enforced by the database rather than by intention.
        let edit = sqlx::query("UPDATE log_commitments SET entries = 99 WHERE id = $1")
            .bind(written.id)
            .execute(&pool)
            .await;
        assert!(edit.is_err(), "a settled commitment must not be rewritable");
        let del = sqlx::query("DELETE FROM log_commitments WHERE id = $1")
            .bind(written.id)
            .execute(&pool)
            .await;
        assert!(del.is_err(), "a settled commitment must not be deletable");

        // And it is still there to be read after both attempts.
        let listed = list_log_commitments(&pool, 0, 100).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].entries, 3);
    }

    /// The detection story, end to end: a registrar that truncates its log
    /// produces a head that CONTRADICTS a commitment it already published.
    /// Nothing here can stop the truncation — the point is that it stops being
    /// invisible.
    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn truncating_the_log_contradicts_the_published_commitment() {
        if !enabled("truncating_the_log_contradicts_the_published_commitment") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        for i in 0..5 {
            log_action(&pool, "claimed", &format!("a{i}.ann@gmail.com"), "ann@gmail.com", serde_json::json!({}))
                .await
                .unwrap();
        }
        let head = current_log_head(&pool).await.unwrap().unwrap();
        let at = Utc::now();
        let published = record_log_commitment(&pool, "https://r.example", &head, &at, "kid1", "c2ln")
            .await
            .unwrap();
        assert_eq!(published.entries, 5);

        // The attack: drop history and carry on. handle_log's own trigger blocks
        // a row-level DELETE, so a registrar doing this has to go around it —
        // which is exactly what an operator with database access can do, and why
        // the evidence has to have been published already.
        sqlx::query("ALTER TABLE handle_log DISABLE TRIGGER USER").execute(&pool).await.unwrap();
        sqlx::query("DELETE FROM handle_log WHERE id <= $1").bind(head.seq - 2).execute(&pool).await.unwrap();
        sqlx::query("ALTER TABLE handle_log ENABLE TRIGGER USER").execute(&pool).await.unwrap();

        let after = current_log_head(&pool).await.unwrap().unwrap();
        assert!(after.entries < published.entries, "the chain got shorter");

        // A verifier holding the old commitment recomputes its bytes against the
        // registrar's current state and finds they no longer describe it. The
        // signature is over the OLD numbers, so the registrar cannot produce a
        // valid commitment for the new state at the same moment in time.
        let now_bytes = log_commitment_canonical(
            "https://r.example",
            &LogHead { seq: published.head_seq, hash: published.head_hash.clone(), entries: after.entries },
            &at,
        );
        let then_bytes = log_commitment_canonical(
            "https://r.example",
            &LogHead { seq: published.head_seq, hash: published.head_hash.clone(), entries: published.entries },
            &at,
        );
        assert_ne!(now_bytes, then_bytes, "the truncation changes the bytes the signature covers");

        // And the commitment survived the purge, because it lives in its own
        // append-only table. If it had been stored alongside the log it would
        // have gone with it.
        assert_eq!(latest_log_commitment(&pool).await.unwrap().unwrap().entries, 5);
    }
}

#[cfg(test)]
mod log_chain {
    use super::*;
    use chrono::TimeZone;

    const ANCHOR: &str = "ann@gmail.com";
    const TOKEN: &str = "ot_9f1c4e2a7b6d4f0e8a3c5b7d9e1f2a4c";

    fn at(n: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_784_000_000 + n, 0).single().expect("valid timestamp")
    }

    /// Build a row the way `log_action_tx` would have written it, in whichever
    /// shape the cutover puts it.
    fn row(id: i64, action: &str, owner: LogOwner<'_>, prev: &str) -> LogRow {
        let detail = serde_json::json!({});
        let entry_hash = log_entry_hash(id, &at(id), action, &detail, prev, owner);
        let mut r = LogRow {
            id,
            at: at(id),
            action: action.to_string(),
            detail,
            prev_hash: Some(prev.to_string()),
            entry_hash: Some(entry_hash),
            email: None,
            handle: None,
            owner_token: None,
            handle_name: None,
        };
        match owner {
            LogOwner::Anchor { handle, email } => {
                r.handle = Some(handle.to_string());
                r.email = Some(email.to_string());
            }
            LogOwner::Token { handle_name, owner_token } => {
                r.handle_name = handle_name.map(str::to_string);
                r.owner_token = Some(owner_token.to_string());
            }
        }
        r
    }

    /// Two pre-cutover rows then two post-cutover ones, linked by prev_hash.
    fn chain_across_cutover() -> Vec<LogRow> {
        let mut rows = Vec::new();
        let mut prev = String::new();
        for (id, action) in [(1i64, "claimed"), (2, "bound")] {
            let r = row(
                id,
                action,
                LogOwner::Anchor { handle: "PublicAgent.ann@gmail.com", email: ANCHOR },
                &prev,
            );
            prev = r.entry_hash.clone().unwrap();
            rows.push(r);
        }
        for (id, action, name) in
            [(3i64, "bound", Some("PublicAgent")), (4, "operator", None)]
        {
            let r = row(id, action, LogOwner::Token { handle_name: name, owner_token: TOKEN }, &prev);
            prev = r.entry_hash.clone().unwrap();
            rows.push(r);
        }
        rows
    }

    /// The pre-cutover rule must not drift by a byte: rows already written under
    /// it are chained and cannot be recomputed, so a change here would make
    /// existing history fail to verify. This literal is the old canonical form.
    #[test]
    fn pre_cutover_canonical_is_frozen() {
        let c = log_entry_canonical(
            1,
            &at(1),
            "claimed",
            &serde_json::json!({}),
            "",
            LogOwner::Anchor { handle: "PublicAgent.ann@gmail.com", email: ANCHOR },
        );
        assert_eq!(
            c,
            r#"{"action":"claimed","at":"2026-07-14T03:33:21.000000Z","detail":{},"email":"ann@gmail.com","handle":"PublicAgent.ann@gmail.com","prev_hash":"","seq":1}"#
        );
    }

    /// The post-cutover rule hashes the token and the anchor-free name, and
    /// nothing else about the owner.
    #[test]
    fn post_cutover_canonical_carries_token_not_email() {
        let c = log_entry_canonical(
            3,
            &at(3),
            "bound",
            &serde_json::json!({}),
            "prevhash",
            LogOwner::Token { handle_name: Some("PublicAgent"), owner_token: TOKEN },
        );
        assert_eq!(
            c,
            format!(
                r#"{{"action":"bound","at":"2026-07-14T03:33:23.000000Z","detail":{{}},"handle_name":"PublicAgent","owner_token":"{TOKEN}","prev_hash":"prevhash","seq":3}}"#
            )
        );
        assert!(!c.contains(ANCHOR), "post-cutover canonical must not contain the address");
        assert!(!c.contains("gmail"), "post-cutover canonical must not contain the anchor domain");
    }

    /// One chain, two rules: it verifies end to end across the cutover.
    #[test]
    fn chain_verifies_across_the_cutover() {
        let rows = chain_across_cutover();
        assert_eq!(verify_log_chain(&rows).expect("chain verifies"), 4);
    }

    /// THE CENTRAL CLAIM. `forget_anchor` deletes a row of `log_owner_tokens` and
    /// touches no `handle_log` row, so the log rows a verifier sees are byte-for-byte
    /// identical before and after. Verification takes only those rows — there is no
    /// mapping in `verify_log_chain`'s signature to consult — so the chain that
    /// verified before the shred verifies after it.
    #[test]
    fn shredding_the_mapping_leaves_the_chain_verifying() {
        let rows = chain_across_cutover();

        // A live mapping: token -> address. This is the only place the link exists
        // for the post-cutover rows.
        let mut mapping: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        mapping.insert(TOKEN, ANCHOR);
        assert_eq!(verify_log_chain(&rows).expect("verifies before the shred"), 4);
        assert_eq!(mapping.get(TOKEN), Some(&ANCHOR));

        // The shred. Nothing else happens: no row is deleted, updated, or re-chained.
        mapping.remove(TOKEN);

        assert_eq!(verify_log_chain(&rows).expect("verifies after the shred"), 4);
        assert!(mapping.is_empty());

        // And the post-cutover rows are now unlinkable: nothing stored in them
        // names a person, and the token is random, so there is nothing to
        // recompute the address from.
        for r in rows.iter().filter(|r| r.owner_token.is_some()) {
            let stored = serde_json::to_string(&serde_json::json!({
                "handle": r.handle, "email": r.email,
                "owner_token": r.owner_token, "handle_name": r.handle_name,
                "action": r.action, "detail": r.detail,
            }))
            .unwrap();
            assert!(!stored.contains(ANCHOR), "row {} still carries the address: {stored}", r.id);
            assert!(!stored.contains("gmail"), "row {} still carries the domain: {stored}", r.id);
        }

        // The pre-cutover rows DO still carry it. That is the disclosed residue,
        // not an oversight, and this assertion is here so nobody later claims the
        // shred was total.
        let residue = rows.iter().filter(|r| r.email.as_deref() == Some(ANCHOR)).count();
        assert_eq!(residue, 2, "pre-cutover rows keep their plaintext email by design");
    }

    /// The verifier has teeth: it is not passing because it checks nothing.
    #[test]
    fn tampering_is_detected_on_both_sides_of_the_cutover() {
        // Rewrite a post-cutover name.
        let mut rows = chain_across_cutover();
        rows[2].handle_name = Some("SomeoneElse".into());
        assert!(verify_log_chain(&rows).is_err(), "a rewritten handle_name must fail");

        // Rewrite a pre-cutover email.
        let mut rows = chain_across_cutover();
        rows[0].email = Some("bob@example.com".into());
        assert!(verify_log_chain(&rows).is_err(), "a rewritten email must fail");

        // Re-point a token, the move an operator would make to launder history.
        let mut rows = chain_across_cutover();
        rows[3].owner_token = Some("ot_00000000000000000000000000000000".into());
        assert!(verify_log_chain(&rows).is_err(), "a swapped owner_token must fail");

        // Cut a link.
        let mut rows = chain_across_cutover();
        rows[2].prev_hash = Some("not-the-previous-hash".into());
        assert!(verify_log_chain(&rows).is_err(), "a broken prev_hash must fail");

        // Drop a row from the middle.
        let mut rows = chain_across_cutover();
        rows.remove(1);
        assert!(verify_log_chain(&rows).is_err(), "a deleted row must fail");
    }

    /// A row with no owner at all would be invisible to the one party §6
    /// entitles to read it. The CHECK constraint forbids it; the verifier
    /// refuses it too rather than hashing a shape it cannot name.
    #[test]
    fn a_row_with_no_owner_does_not_verify() {
        let mut rows = chain_across_cutover();
        rows[3].owner_token = None;
        assert!(verify_log_chain(&rows).is_err());
    }

    #[test]
    fn strip_anchor_separates_name_from_anchor() {
        assert_eq!(strip_anchor("PublicAgent.ann@gmail.com", "ann@gmail.com").as_deref(), Some("PublicAgent"));
        // Dotted names: the anchor is stripped as a whole, so there is no
        // last-dot/first-dot ambiguity to get wrong.
        assert_eq!(strip_anchor("My.Agent.ann@gmail.com", "ann@gmail.com").as_deref(), Some("My.Agent"));
        // Domain-tier anchors work the same way.
        assert_eq!(strip_anchor("support.example.com", "example.com").as_deref(), Some("support"));
        // Case differences between the stored handle and the anchor.
        assert_eq!(strip_anchor("PublicAgent.Ann@Gmail.com", "ann@gmail.com").as_deref(), Some("PublicAgent"));
        // The anchor-level sentinel concerns no handle.
        assert_eq!(strip_anchor("-", "ann@gmail.com"), None);
        // No name left over is not a name.
        assert_eq!(strip_anchor(".ann@gmail.com", "ann@gmail.com"), None);
        assert_eq!(strip_anchor("ann@gmail.com", "ann@gmail.com"), None);
        // A mismatch yields None, NOT the raw string: storing the raw string
        // would put the anchor in the one column that survives erasure.
        assert_eq!(strip_anchor("PublicAgent.bob@example.com", "ann@gmail.com"), None);
        assert_eq!(strip_anchor("", "ann@gmail.com"), None);
        assert_eq!(strip_anchor("PublicAgent.ann@gmail.com", ""), None);
        // Multi-byte names must not panic on a byte-index split.
        assert_eq!(strip_anchor("Ünïcödé.ann@gmail.com", "ann@gmail.com").as_deref(), Some("Ünïcödé"));
        assert_eq!(strip_anchor("Ünïcödé", "cödé"), None);
    }

    #[test]
    fn anchor_key_normalizes_so_one_person_gets_one_token() {
        assert_eq!(anchor_key("  Ann@GMail.com "), "ann@gmail.com");
        assert_eq!(anchor_key("ann@gmail.com"), "ann@gmail.com");
    }
}

// The same claims against a real PostgreSQL, because the parts that can only
// fail against a database — the 0013 migration's DO block, CHECK constraint and
// plpgsql triggers, and whether a shred really leaves the chain verifying — are
// exactly the parts a pure test cannot reach.
//
// Gated on PAN_DB_TESTS=1 and skipped otherwise: it boots the embedded
// PostgreSQL the registrar already depends on, which on a cold machine downloads
// the server binaries first. Run it with:
//
//     PAN_DB_TESTS=1 cargo test log_chain_db -- --ignored --test-threads=1
/// A migrated database of one's own, shared by every `PAN_DB_TESTS` module below
/// — and by `crate::http_tests`, which drives the router over a real socket and
/// needs exactly the same thing behind it.
#[cfg(test)]
pub(crate) mod test_db {
    use super::*;

    pub async fn fresh_db() -> (Option<postgresql_embedded::PostgreSQL>, PgPool) {
        // A PostgreSQL server of the caller's (CI's service container, a local
        // install): a fresh database on it per test, so tests never share rows.
        if let Ok(base) = std::env::var("PAN_TEST_DATABASE_URL") {
            let admin = crate::store::connect_with_retry(&base).await;
            let name = format!("pan_test_{}", Uuid::new_v4().simple());
            // The name is ours, built from a UUID, never input.
            sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
                .execute(&admin)
                .await
                .expect("create a test database");
            let url = match base.rsplit_once('/') {
                Some((server, _db)) => format!("{server}/{name}"),
                None => format!("{base}/{name}"),
            };
            let pool = crate::store::connect_with_retry(&url).await;
            crate::store::migrate(&pool).await.expect("migrations apply");
            return (None, pool);
        }
        let dir = std::env::temp_dir().join(format!("pan-log-test-{}", Uuid::new_v4().simple()));
        std::env::set_var("CATALOG_DATA_DIR", &dir);
        // A fresh CLUSTER per test, one INSTALLATION for the whole run. Every
        // test used to get a fresh installation directory too, which meant
        // `postgresql_embedded` asked GitHub for the release list and unpacked the
        // server binaries once per test — slow, and past a handful of tests it
        // hits the unauthenticated API rate limit and the suite fails with a 403
        // about api.github.com that says nothing about PostgreSQL.
        std::env::set_var(
            "CATALOG_PG_RUNTIME_DIR",
            std::env::temp_dir().join("pan-test-postgres-runtime"),
        );
        let (pg, url) = crate::db::start_embedded().await;
        let pool = crate::store::connect_with_retry(&url).await;
        crate::store::migrate(&pool).await.expect("migrations apply");
        (Some(pg), pool)
    }

    /// The gate every one of these tests opens with. Returns false when the
    /// harness is off, so the test reports skipped rather than quietly passing.
    pub fn enabled(name: &str) -> bool {
        if std::env::var("PAN_DB_TESTS").as_deref() == Ok("1") {
            return true;
        }
        eprintln!("skipped {name}: set PAN_DB_TESTS=1");
        false
    }
}

#[cfg(test)]
mod log_chain_db {
    use super::test_db::fresh_db;
    use super::*;

    /// Stand in for history written before migration 0013: plaintext email, whole
    /// handle, chained under the pre-cutover rule.
    async fn insert_pre_cutover(pool: &PgPool, handle: &str, email: &str) -> i64 {
        let prev: Option<String> =
            sqlx::query_scalar("SELECT entry_hash FROM handle_log ORDER BY id DESC LIMIT 1")
                .fetch_optional(pool)
                .await
                .unwrap()
                .flatten();
        let prev = prev.unwrap_or_default();
        let at = Utc::now();
        let detail = serde_json::json!({});
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO handle_log (at, action, handle, email, detail, prev_hash) \
             VALUES ($1, 'claimed', $2, $3, $4, $5) RETURNING id",
        )
        .bind(at)
        .bind(handle)
        .bind(email)
        .bind(&detail)
        .bind(&prev)
        .fetch_one(pool)
        .await
        .unwrap();
        let hash = log_entry_hash(
            id,
            &at,
            "claimed",
            &detail,
            &prev,
            LogOwner::Anchor { handle, email },
        );
        sqlx::query("UPDATE handle_log SET entry_hash = $1 WHERE id = $2 AND entry_hash IS NULL")
            .bind(hash)
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn shredding_a_mapping_leaves_the_real_chain_verifying() {
        if std::env::var("PAN_DB_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped: set PAN_DB_TESTS=1");
            return;
        }
        let (_pg, pool) = fresh_db().await;

        let email = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let handle = format!("PublicAgent.{email}");

        // One row from before the cutover, then three appended the new way.
        let pre_id = insert_pre_cutover(&pool, &handle, &email).await;
        log_action(&pool, "claimed", &handle, &email, serde_json::json!({ "via": "email" }))
            .await
            .expect("append 1");
        log_action(&pool, "bound", &handle, &email, serde_json::json!({ "method": "agent-key" }))
            .await
            .expect("append 2");
        log_action(&pool, "operator", "-", &email, serde_json::json!({ "display_name": "Ann" }))
            .await
            .expect("append 3");

        // The post-cutover rows must carry a token and neither email nor handle.
        let post: Vec<(i64, Option<String>, Option<String>, Option<String>, Option<String>)> =
            sqlx::query_as(
                "SELECT id, email, handle, owner_token, handle_name FROM handle_log \
                 WHERE id > $1 ORDER BY id",
            )
            .bind(pre_id)
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(post.len(), 3);
        for (id, e, h, tok, _name) in &post {
            assert!(e.is_none(), "row {id} still stores an email");
            assert!(h.is_none(), "row {id} still stores a handle");
            assert!(tok.is_some(), "row {id} has no owner token");
        }
        // The handle's name survives; the anchor does not.
        assert_eq!(post[0].4.as_deref(), Some("PublicAgent"));
        assert_eq!(post[2].4, None, "an anchor-level action has no handle name");

        // The chain verifies end to end, across the cutover.
        let rows = log_rows(&pool, 0, 10_000).await.unwrap();
        let checked_before = verify_log_chain(&rows).expect("chain verifies before the shred");
        assert!(checked_before >= 4);

        // The owner can read their own history: all four rows, handles reassembled.
        let entries = log_entries(&pool, &email, 100).await.unwrap();
        assert_eq!(entries.len(), 4);
        assert!(entries.iter().any(|e| e["handle"] == serde_json::json!(handle.as_str())));

        // THE SHRED.
        let outcome = forget_anchor(&pool, &email).await.expect("forget");
        assert!(outcome.mapping_deleted);
        assert_eq!(outcome.rows_unlinked, 3);
        assert_eq!(outcome.rows_still_plaintext, 1, "the pre-cutover row is the disclosed residue");
        assert_eq!(outcome.live_handles, 0);

        // THE CENTRAL CLAIM: same rows, same count, still verifying.
        let rows_after = log_rows(&pool, 0, 10_000).await.unwrap();
        assert_eq!(rows_after.len(), rows.len(), "no log row was deleted");
        assert_eq!(
            verify_log_chain(&rows_after).expect("chain verifies after the shred"),
            checked_before
        );

        // And the post-cutover rows are no longer reachable from the person: only
        // the pre-cutover residue comes back.
        let after = log_entries(&pool, &email, 100).await.unwrap();
        assert_eq!(after.len(), 1, "only the un-erasable pre-cutover row remains linked");
        assert_eq!(after[0]["seq"], serde_json::json!(pre_id));

        // Shredding twice is not an error, and reports honestly that there was
        // nothing left to delete.
        let again = forget_anchor(&pool, &email).await.expect("second forget");
        assert!(!again.mapping_deleted);
        assert_eq!(again.rows_unlinked, 0);
        assert_eq!(again.rows_still_plaintext, 1);

        // Coming back gets a NEW token, so returning does not re-link the erased
        // history to the person.
        log_action(&pool, "claimed", &handle, &email, serde_json::json!({})).await.expect("re-append");
        let relinked = log_entries(&pool, &email, 100).await.unwrap();
        assert_eq!(relinked.len(), 2, "the new entry plus the residue, not the erased three");
        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }

    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn the_database_refuses_to_rewrite_or_delete_settled_rows() {
        if std::env::var("PAN_DB_TESTS").as_deref() != Ok("1") {
            eprintln!("skipped: set PAN_DB_TESTS=1");
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("bob-{}@example.com", Uuid::new_v4().simple());
        let handle = format!("Agent.{email}");
        log_action(&pool, "claimed", &handle, &email, serde_json::json!({})).await.expect("append");
        let id: i64 = sqlx::query_scalar("SELECT id FROM handle_log ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();

        // Rewriting a settled row's content.
        let e = sqlx::query("UPDATE handle_log SET action = 'released' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect_err("the trigger must refuse a content rewrite");
        assert!(format!("{e}").contains("settled"), "unexpected error: {e}");

        // Re-hashing a settled row, the move that would launder a rewrite.
        let e = sqlx::query("UPDATE handle_log SET entry_hash = 'forged' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect_err("the trigger must refuse a re-hash");
        assert!(format!("{e}").contains("settled"), "unexpected error: {e}");

        // Deleting.
        let e = sqlx::query("DELETE FROM handle_log WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect_err("the trigger must refuse a DELETE");
        assert!(format!("{e}").contains("append-only"), "unexpected error: {e}");

        // Truncating, which row triggers do not see.
        let e = sqlx::query("TRUNCATE handle_log")
            .execute(&pool)
            .await
            .expect_err("the trigger must refuse a TRUNCATE");
        assert!(format!("{e}").contains("append-only"), "unexpected error: {e}");

        // And the shape CHECK admits neither a hybrid row nor an ownerless one.
        let e = sqlx::query(
            "INSERT INTO handle_log (action, handle, email, owner_token) \
             VALUES ('claimed', 'A.b@c.d', 'b@c.d', 'ot_x')",
        )
        .execute(&pool)
        .await
        .expect_err("a row carrying both shapes must be refused");
        assert!(format!("{e}").contains("handle_log_owner_shape"), "unexpected error: {e}");

        let e = sqlx::query("INSERT INTO handle_log (action) VALUES ('claimed')")
            .execute(&pool)
            .await
            .expect_err("a row carrying no owner must be refused");
        assert!(format!("{e}").contains("handle_log_owner_shape"), "unexpected error: {e}");

        // The chain is intact after every refusal.
        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }
}

// Who may release whose name (§3.1). The shape check runs with no database, so
// the refusal that carries the security property is covered by plain `cargo test`;
// `release_scope_db` below proves the same refusal against real rows, plus the
// tombstone, the log attribution and the cooling-off window.
#[cfg(test)]
mod release_scope {
    use super::*;

    #[test]
    fn a_delegated_session_may_only_name_its_own_anchors_handles() {
        let ann = "ann@gmail.com";
        assert!(handle_anchors_to("PublicAgent.ann@gmail.com", ann));
        // Dotted names are still one anchor's.
        assert!(handle_anchors_to("My.Work.Agent.ann@gmail.com", ann));
        // Whitespace and case are how the same request arrives twice, not how a
        // different anchor sneaks in.
        assert!(handle_anchors_to("  PublicAgent.Ann@GMail.com  ", ann));

        // THE REFUSAL. Another anchor's handle, in every way a caller might try
        // to make one look like it anchors here.
        assert!(!handle_anchors_to("PublicAgent.bob@example.com", ann));
        // Ann's address as the handle's NAME, someone else's as its anchor.
        assert!(!handle_anchors_to("ann@gmail.com.bob@example.com", ann));
        // A suffix that merely ends the same way: mann@gmail.com is not ann@gmail.com.
        assert!(!handle_anchors_to("PublicAgent.mann@gmail.com", ann));
        // The anchor with no name in front of it is not a handle at all.
        assert!(!handle_anchors_to("ann@gmail.com", ann));
        assert!(!handle_anchors_to(".ann@gmail.com", ann));
        // A subdomain of the anchor's domain is a different anchor.
        assert!(!handle_anchors_to("PublicAgent.ann@mail.gmail.com", ann));
        // Empties refuse rather than match everything.
        assert!(!handle_anchors_to("", ann));
        assert!(!handle_anchors_to("PublicAgent.ann@gmail.com", ""));
        assert!(!handle_anchors_to("", ""));
        // The anchor-level log sentinel is not releasable.
        assert!(!handle_anchors_to("-", ann));
        // A multi-byte name must refuse, not panic on a byte-index split.
        assert!(!handle_anchors_to("Ünïcödé.bob@example.com", ann));
    }
}

// The database-level half: the refusal against real rows, and the three things
// release must not stop doing.
//
//     PAN_DB_TESTS=1 cargo test release_scope_db -- --ignored --test-threads=1
#[cfg(test)]
mod release_scope_db {
    use super::test_db::{enabled, fresh_db};
    use super::*;

    /// The `released` entries an anchor can see, newest first.
    async fn releases_of(pool: &PgPool, email: &str) -> Vec<serde_json::Value> {
        log_entries(pool, email, 500)
            .await
            .expect("owner-scoped log read")
            .into_iter()
            .filter(|e| e["action"] == serde_json::json!("released"))
            .collect()
    }

    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn a_delegated_release_is_logged_as_the_owner_and_cools_off() {
        if !enabled("a_delegated_release_is_logged_as_the_owner_and_cools_off") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let handle = claim(&pool, &email, "PublicAgent", None, "delegated:agentmesh")
            .await
            .expect("claim");

        let out = release_by_anchor(&pool, &email, &handle, "delegated:agentmesh")
            .await
            .expect("an anchor may release its own handle");

        // The tombstone: gone from resolution and from the owner's roster, and the
        // cooling-off window is reported, not merely implied.
        assert_eq!(out.handle, handle);
        assert!(resolve(&pool, &handle).await.unwrap().is_none(), "a released handle must not resolve");
        assert!(mine(&pool, &email).await.unwrap().is_empty(), "a released handle must leave the roster");
        assert_eq!(
            (out.claimable_after - out.released_at).num_days(),
            COOLING_OFF_DAYS,
            "the reported window must be the one claim enforces"
        );

        // THE ATTRIBUTION. One `released` entry, the ordinary owner action, with
        // the delegated provenance disclosed in it (§3.1) — and emphatically not
        // `released_by_operator`, which would say the operator took the name.
        let releases = releases_of(&pool, &email).await;
        assert_eq!(releases.len(), 1, "exactly one release entry");
        assert_eq!(releases[0]["handle"], serde_json::json!(handle));
        assert_eq!(releases[0]["detail"]["via"], serde_json::json!("delegated:agentmesh"));
        let all = log_entries(&pool, &email, 500).await.unwrap();
        assert!(
            !all.iter().any(|e| e["action"] == serde_json::json!("released_by_operator")),
            "a user-initiated release must not be recorded as operator moderation"
        );

        // The cooling-off window survives: the name is not immediately re-claimable,
        // not even by the anchor that just gave it up.
        let again = claim(&pool, &email, "PublicAgent", None, "email").await;
        assert!(
            matches!(&again, Err(RegistrarError::Taken(m)) if m.contains("cooling-off")),
            "expected a cooling-off refusal, got {again:?}"
        );

        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }

    /// The platform's rename (services/src/api/agent-rename.ts) is three acts it
    /// already had: a delegated claim, a delegated bind of the SAME key, and a
    /// delegated release of the old handle. This holds what the rename leans on:
    /// the key keeps one record, the new name resolves to it with no key change
    /// on its card, the old name stops resolving, reverse resolution answers the
    /// new name, and the old name is held from everyone for the cooling-off.
    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn a_rename_keeps_the_key_moves_the_name_and_cools_the_old_one() {
        if !enabled("a_rename_keeps_the_key_moves_the_name_and_cools_the_old_one") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let bob = format!("bob-{}@example.com", Uuid::new_v4().simple());
        let (key, _seed) = crate::test_identity().expect("key");

        let old = claim(&pool, &email, "scout", None, "delegated:agentmesh").await.expect("old claim");
        pair_delegated(&pool, &email, "agentmesh", &old, &key, false).await.expect("old bind");

        // The rename, in the platform's order: the new name first, bound to the
        // same key, and only then the old name given up.
        let new = claim(&pool, &email, "ranger", None, "delegated:agentmesh").await.expect("new claim");
        pair_delegated(&pool, &email, "agentmesh", &new, &key, false).await.expect("new bind");
        let by_key = resolve_by_agent(&pool, &key).await.unwrap().expect("the key resolves");
        assert_eq!(by_key.handle, new, "while both are bound, the key answers its newest name");
        release_by_anchor(&pool, &email, &old, "delegated:agentmesh").await.expect("old release");

        // The old name no longer resolves; the new one resolves to the same key.
        assert!(resolve(&pool, &old).await.unwrap().is_none(), "a released name must not resolve");
        let now = resolve(&pool, &new).await.unwrap().expect("the new name resolves");
        let was = sqlx::query_as::<_, (Uuid,)>("SELECT listing_id FROM handles WHERE handle_key = lower($1)")
            .bind(&old)
            .fetch_one(&pool)
            .await
            .unwrap()
            .0;
        assert_eq!(now.listing_id, Some(was), "one agent record: the key did not change");
        assert_eq!(resolve_by_agent(&pool, &key).await.unwrap().expect("by key").handle, new);
        // A first binding of a fresh name is not a key change, so a resolver
        // pinning the new name sees nothing to warn about.
        assert!(key_history(&pool, &new).await.unwrap().is_empty(), "the rename is not a key change");
        assert_eq!(mine(&pool, &email).await.unwrap().len(), 1, "the owner holds the new name only");

        // The old name is held from everyone for the cooling-off period, its
        // former owner included, and another anchor cannot take the new one.
        let again = claim(&pool, &email, "scout", None, "delegated:agentmesh").await;
        assert!(
            matches!(&again, Err(RegistrarError::Taken(m)) if m.contains("cooling-off")),
            "expected a cooling-off refusal, got {again:?}"
        );
        let stolen = release_by_anchor(&pool, &bob, &new, "delegated:agentmesh").await;
        assert!(matches!(&stolen, Err(RegistrarError::Forbidden(_))), "another anchor cannot release it: {stolen:?}");
        assert!(resolve(&pool, &new).await.unwrap().is_some());

        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }

    /// §5.8: between the bind and the release, the old name keeps resolving
    /// with a notice; past its window it stops, and after its release it
    /// answers "moved to" the new name for the cooling-off period.
    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn a_renamed_name_resolves_with_a_notice_then_answers_moved_to() {
        if !enabled("a_renamed_name_resolves_with_a_notice_then_answers_moved_to") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let bob = format!("bob-{}@example.com", Uuid::new_v4().simple());
        let (key, _seed) = crate::test_identity().expect("key");
        let (other, _seed2) = crate::test_identity().expect("other key");

        let old = claim(&pool, &email, "scout", None, "delegated:agentmesh").await.expect("old claim");
        pair_delegated(&pool, &email, "agentmesh", &old, &key, false).await.expect("old bind");
        let new = claim(&pool, &email, "ranger", None, "delegated:agentmesh").await.expect("new claim");
        let elsewhere = claim(&pool, &email, "other", None, "delegated:agentmesh").await.expect("third claim");
        pair_delegated(&pool, &email, "agentmesh", &elsewhere, &other, false).await.expect("third bind");

        // Not before the new name is bound to the same agent, and not to another agent's name.
        let early = set_rename_window(&pool, &email, &old, &new, 30, "delegated:agentmesh").await;
        assert!(matches!(&early, Err(RegistrarError::Invalid(_))), "{early:?}");
        let wrong = set_rename_window(&pool, &email, &old, &elsewhere, 30, "delegated:agentmesh").await;
        assert!(matches!(&wrong, Err(RegistrarError::Invalid(_))), "{wrong:?}");

        pair_delegated(&pool, &email, "agentmesh", &new, &key, false).await.expect("new bind");
        let stolen = set_rename_window(&pool, &bob, &old, &new, 30, "delegated:agentmesh").await;
        assert!(matches!(&stolen, Err(RegistrarError::Forbidden(_))), "{stolen:?}");
        let until = set_rename_window(&pool, &email, &old, &new, 30, "delegated:agentmesh").await.expect("window");
        assert!(until > Utc::now() + chrono::Duration::days(29));

        // The window: the old name resolves, to the same agent, with a notice.
        let h = resolve(&pool, &old).await.unwrap().expect("the old name resolves in its window");
        let n = rename_notice(&h, Utc::now()).expect("with a notice");
        assert_eq!(n.renamed_to.to_lowercase(), new.to_lowercase());
        assert_eq!(resolve_by_agent(&pool, &key).await.unwrap().expect("by key").handle, new, "the key answers the new name");
        assert!(resolve_moved(&pool, &old).await.unwrap().is_none(), "not moved while the window is open");

        // Past the window: no longer resolving, answering moved to.
        sqlx::query("UPDATE handles SET renamed_until = now() - interval '1 minute' WHERE handle_key = lower($1)")
            .bind(&old)
            .execute(&pool)
            .await
            .unwrap();
        let h = resolve(&pool, &old).await.unwrap().expect("the row is still there");
        assert!(rename_window_closed(&h, Utc::now()), "a closed window must not resolve");
        assert_eq!(resolve_moved(&pool, &old).await.unwrap().map(|(_, to, _)| to.to_lowercase()), Some(new.to_lowercase()));

        // Released: still "moved to" for the cooling-off, and held from everyone.
        release_by_anchor(&pool, &email, &old, "delegated:agentmesh").await.expect("release");
        assert!(resolve(&pool, &old).await.unwrap().is_none());
        assert!(resolve_moved(&pool, &old).await.unwrap().is_some(), "moved to, through the cooling-off");
        let again = claim(&pool, &email, "scout", None, "delegated:agentmesh").await;
        assert!(matches!(&again, Err(RegistrarError::Taken(_))), "{again:?}");
        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }

    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn releasing_another_anchors_handle_is_refused_and_changes_nothing() {
        if !enabled("releasing_another_anchors_handle_is_refused_and_changes_nothing") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let ann = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let bob = format!("bob-{}@example.com", Uuid::new_v4().simple());
        let bobs = claim(&pool, &bob, "PublicAgent", None, "email").await.expect("bob claims");

        let refused = release_by_anchor(&pool, &ann, &bobs, "delegated:agentmesh").await;
        assert!(
            matches!(&refused, Err(RegistrarError::Forbidden(m)) if m.contains("different email address")),
            "expected a Forbidden anchor refusal, got {refused:?}"
        );

        // Refused means untouched: bob still has his name, and nothing was written
        // to a log that cannot take anything back.
        assert!(resolve(&pool, &bobs).await.unwrap().is_some(), "bob's handle must survive");
        assert_eq!(mine(&pool, &bob).await.unwrap().len(), 1);
        assert!(releases_of(&pool, &bob).await.is_empty(), "no release may be logged against bob");
        assert!(releases_of(&pool, &ann).await.is_empty(), "no release may be logged against ann");

        // A name that does not exist is a different answer from a name that is not
        // yours — the caller needs to tell a no-op apart from its own bug.
        let missing = release_by_anchor(&pool, &ann, &format!("Nope.{ann}"), "delegated:agentmesh").await;
        assert!(
            matches!(&missing, Err(RegistrarError::Invalid(m)) if m.contains("no active handle")),
            "expected an Invalid not-found, got {missing:?}"
        );

        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }

    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn the_direct_owner_path_still_logs_a_plain_release() {
        if !enabled("the_direct_owner_path_still_logs_a_plain_release") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("cara-{}@example.com", Uuid::new_v4().simple());
        let handle = claim(&pool, &email, "Desk", None, "email").await.expect("claim");

        release(&pool, &email, &handle).await.expect("the owner's own release still works");

        assert!(resolve(&pool, &handle).await.unwrap().is_none());
        let releases = releases_of(&pool, &email).await;
        assert_eq!(releases.len(), 1);
        // Unchanged on purpose: a direct release carries no `via`, and absence is
        // what distinguishes it from a delegated one.
        assert_eq!(releases[0]["detail"], serde_json::json!({}));
    }
}

// §4.4: a rebind is recorded where the readers of the name can see it. These
// need a database because the record is written inside the same transactions
// that rebind, and the append-only guard is a database trigger.
//
//     PAN_DB_TESTS=1 cargo test key_history_db -- --ignored --test-threads=1
#[cfg(test)]
mod key_history_db {
    use super::test_db::{enabled, fresh_db};
    use super::*;

    /// Run the §4.1 ceremony end to end for an existing identity.
    async fn pair_with(pool: &PgPool, email: &str, handle: &str, public: &str, seed: &str) {
        use base64::Engine;
        let (code, _) = pair_start(pool, email, handle).await.expect("pair start");
        let kp = nkeys::KeyPair::from_seed(seed).expect("keypair from seed");
        let sig = kp.sign(format!("pan-pair-v1:{code}:{public}").as_bytes()).expect("sign");
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig);
        pair_complete(pool, &code, public, &sig_b64).await.expect("pair complete");
    }

    /// The lifecycle a counterparty needs to be able to read: first bind is not
    /// a change, re-pairing the same key is not a change, re-pairing a NEW key
    /// is, a delegated rebind is, and a detachment is. Every change lands in
    /// `key_history` with the method that caused it, and the owner's own §6
    /// history names the replaced key too.
    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn every_change_of_the_key_behind_a_name_is_recorded() {
        if !enabled("every_change_of_the_key_behind_a_name_is_recorded") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let handle = claim(&pool, &email, "PublicAgent", None, "email").await.expect("claim");

        // First bind: the name had no key, so nothing changed.
        let (k1, seed1) = crate::test_identity().expect("k1");
        pair_with(&pool, &email, &handle, &k1, &seed1).await;
        assert!(key_history(&pool, &handle).await.unwrap().is_empty(), "a first bind is not a change");

        // Re-pairing the SAME key (a retry, a machine move): still nothing.
        pair_with(&pool, &email, &handle, &k1, &seed1).await;
        assert!(key_history(&pool, &handle).await.unwrap().is_empty(), "the same key again is not a change");

        // THE REBIND. One ceremony re-points the trusted name at a brand new
        // key, and that is exactly what must become readable.
        let (k2, seed2) = crate::test_identity().expect("k2");
        pair_with(&pool, &email, &handle, &k2, &seed2).await;
        let history = key_history(&pool, &handle).await.unwrap();
        assert_eq!(history.len(), 1, "the rebind is one recorded change");
        assert_eq!(history[0].old_key, k1);
        assert_eq!(history[0].new_key.as_deref(), Some(k2.as_str()));
        assert_eq!(history[0].method, "agent-key");

        // The owner's §6 history names the replaced key as well.
        let entries = log_entries(&pool, &email, 100).await.unwrap();
        let rebind = entries
            .iter()
            .find(|e| e["detail"]["previous_agent_id"] == serde_json::json!(k1))
            .expect("the bound entry that replaced a key names the key it replaced");
        assert_eq!(rebind["action"], serde_json::json!("bound"));
        assert_eq!(rebind["detail"]["agent_id"], serde_json::json!(k2));

        // A delegated binding (§4.3) can rebind too, and records its method.
        let (k3, _seed3) = crate::test_identity().expect("k3");
        pair_delegated(&pool, &email, "partner", &handle, &k3, false).await.expect("delegated bind");
        let history = key_history(&pool, &handle).await.unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[1].old_key, k2);
        assert_eq!(history[1].new_key.as_deref(), Some(k3.as_str()));
        assert_eq!(history[1].method, "agent-key-delegated:partner");
        assert!(!history[0].old_key_revoked && !history[1].old_key_revoked, "a machine move revokes nothing");

        // A rotation after a leak (SPEC.md §5.3): the owner says the key being
        // replaced is revoked, and the change record says so.
        let (k4, _seed4) = crate::test_identity().expect("k4");
        pair_delegated(&pool, &email, "partner", &handle, &k4, true).await.expect("rotation");
        let history = key_history(&pool, &handle).await.unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[2].old_key, k3);
        assert_eq!(history[2].new_key.as_deref(), Some(k4.as_str()));
        assert!(history[2].old_key_revoked, "the leaked key is recorded as revoked");
        let entries = log_entries(&pool, &email, 100).await.unwrap();
        assert!(
            entries.iter().any(|e| e["detail"]["previous_key_revoked"] == serde_json::json!(true)),
            "the owner's history says the replaced key was revoked"
        );

        // Detaching removes the key behind the name; recorded, or a
        // detach-then-re-pair would change keys with no entry saying so.
        bind(&pool, &email, &handle, None).await.expect("detach");
        let history = key_history(&pool, &handle).await.unwrap();
        assert_eq!(history.len(), 4);
        assert_eq!(history[3].old_key, k4);
        assert_eq!(history[3].new_key, None, "a detachment records no new key");
        assert_eq!(history[3].method, "email-submitter");

        // And the §6 chain is intact through all of it.
        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }

    /// The record serves the CURRENT claim only, and cannot be rewritten.
    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn history_is_scoped_to_the_current_claim_and_is_append_only() {
        if !enabled("history_is_scoped_to_the_current_claim_and_is_append_only") {
            return;
        }
        let (_pg, pool) = fresh_db().await;
        let email = format!("bob-{}@example.com", Uuid::new_v4().simple());
        let handle = claim(&pool, &email, "Desk", None, "email").await.expect("claim");
        let key = handle.to_lowercase();

        // A change from an earlier claim of the same name (before a release and
        // cooling-off): present in the table, not served for this claim.
        sqlx::query(
            "INSERT INTO handle_key_changes (handle_key, old_key, new_key, method, changed_at) \
             VALUES ($1, 'UOLDKEY', 'UNEWKEY', 'agent-key', now() - interval '400 days')",
        )
        .bind(&key)
        .execute(&pool)
        .await
        .expect("an earlier era's row");
        assert!(
            key_history(&pool, &handle).await.unwrap().is_empty(),
            "an earlier claim's changes describe somebody else's agent and must not be served"
        );

        // This claim's own change IS served.
        let (k1, seed1) = crate::test_identity().expect("k1");
        pair_with(&pool, &email, &handle,&k1, &seed1).await;
        let (k2, seed2) = crate::test_identity().expect("k2");
        pair_with(&pool, &email, &handle,&k2, &seed2).await;
        let history = key_history(&pool, &handle).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].old_key, k1);

        // Append-only, enforced by the database: a history readers rely on must
        // not be editable after the fact.
        let id: i64 = sqlx::query_scalar(
            "SELECT id FROM handle_key_changes WHERE handle_key = $1 ORDER BY id DESC LIMIT 1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .unwrap();
        let edit = sqlx::query("UPDATE handle_key_changes SET old_key = 'ULAUNDERED' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await;
        assert!(edit.is_err(), "a recorded key change must not be rewritable");
        let del = sqlx::query("DELETE FROM handle_key_changes WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await;
        assert!(del.is_err(), "a recorded key change must not be deletable");

        // A row recording no change is refused by shape.
        let noop = sqlx::query(
            "INSERT INTO handle_key_changes (handle_key, old_key, new_key, method) \
             VALUES ($1, 'USAME', 'USAME', 'agent-key')",
        )
        .bind(&key)
        .execute(&pool)
        .await;
        assert!(noop.is_err(), "old and new key equal is not a change record");
    }
}

// Wire-format conformance against ../../conformance/naming.json — the fixture
// the JS side (mesh-adapter/test/conformance.mjs) also asserts. If a test
// here fails after an edit, the fix is to agree with the fixture, not to
// update it casually: deployed adapters hold pins over these exact bytes.
#[cfg(test)]
mod conformance {
    use super::canonical_json;

    fn fixture() -> serde_json::Value {
        let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/conformance/naming.json"))
            .expect("conformance/naming.json");
        serde_json::from_str(&raw).expect("fixture parses")
    }

    #[test]
    fn pair_canonical_matches() {
        let f = fixture();
        let code = f["pair"]["code"].as_str().unwrap();
        let agent_id = f["pair"]["agent_id"].as_str().unwrap();
        // Mirrors verify_pairing below.
        let msg = format!("pan-pair-v1:{code}:{agent_id}");
        assert_eq!(msg, f["pair"]["canonical"].as_str().unwrap());
    }

    #[test]
    fn checkin_v3_canonical_matches() {
        let f = fixture();
        let c = &f["checkin_v3"];
        // Mirrors the v3 check-in canonical (newline-joined).
        let msg = [
            "pan-checkin-v3".to_string(),
            c["ts"].as_i64().unwrap().to_string(),
            c["agent_id"].as_str().unwrap().to_string(),
            c["kind"].as_str().unwrap().to_string(),
            c["host"].as_str().unwrap().to_string(),
            c["platform"].as_str().unwrap().to_string(),
            c["encryption_key"].as_str().unwrap().to_string(),
        ]
        .join("\n");
        assert_eq!(msg, c["canonical"].as_str().unwrap());
    }

    #[test]
    fn card_canonical_json_matches() {
        let f = fixture();
        assert_eq!(
            canonical_json(&f["card"]["value"]),
            f["card"]["canonical"].as_str().unwrap()
        );
    }
}

// Migration 0014, run against real rows. The write path that produced those rows
// is fixed in `rehome_in` above; this is about the repair, and specifically about
// the two claims a data migration has to earn before it is allowed near
// production: that it cannot collide with an existing row, and that it cannot
// change which handle resolves.
//
// It executes the migration FILE, not a copy of its statements, so the bytes
// asserted here are the bytes production applies.
//
//     PAN_DB_TESTS=1 cargo test rehome_normalization_db -- --ignored --test-threads=1
#[cfg(test)]
mod rehome_normalization_db {
    use super::test_db::{enabled, fresh_db};
    use super::*;

    const MIGRATION_0014: &str =
        include_str!("../migrations/0014_normalize_rehomed_anchor.sql");

    /// A handle row exactly as the un-normalized `rehome_in` wrote one: display
    /// handle and `handle_key` correct, `email` carrying the case the SIGNER chose,
    /// and the anchor TIER column holding an address instead of 'email'.
    async fn insert_as_the_bug_did(pool: &PgPool, display: &str, anchor_as_written: &str) {
        sqlx::query(
            "INSERT INTO handles (handle, handle_key, email, anchor, bind_method, claimed_via, verified_at) \
             VALUES ($1, lower($1), $2, $2, 'agent-key', 'rehomed:https://old.example', now())",
        )
        .bind(display)
        .bind(anchor_as_written)
        .execute(pool)
        .await
        .expect("insert a pre-fix row");
    }

    async fn operator_rows(pool: &PgPool) -> Vec<(String, String)> {
        sqlx::query_as("SELECT email, display_name FROM operators ORDER BY email")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "boots an embedded PostgreSQL; set PAN_DB_TESTS=1"]
    async fn normalizing_a_rehomed_anchor_hands_the_handle_back_to_its_owner() {
        if !enabled("normalizing_a_rehomed_anchor_hands_the_handle_back_to_its_owner") {
            return;
        }
        let (_pg, pool) = fresh_db().await;

        // Ann has one ordinary handle, so she has a normalized operator row with
        // the display name she chose. This is the collision case for `operators`,
        // whose email column is a PRIMARY KEY.
        let ann = format!("ann-{}@example.com", Uuid::new_v4().simple());
        let ann_mixed = ann.to_uppercase();
        claim(&pool, &ann, "Direct", None, "email").await.expect("ann claims");
        operator_set(&pool, &ann, "Ann Herself").await.expect("ann names herself");

        // And one handle that arrived by migration in, written the broken way.
        let moved = format!("Moved.{ann_mixed}");
        insert_as_the_bug_did(&pool, &moved, &ann_mixed).await;
        sqlx::query("INSERT INTO operators (email, display_name) VALUES ($1, 'ann')")
            .bind(&ann_mixed)
            .execute(&pool)
            .await
            .expect("the duplicate operator row rehome_in created");

        // Bob has ONLY the broken row: no normalized twin, so his operator row
        // must be renamed rather than folded away. The two branches of step 1.
        let bob = format!("bob-{}@example.com", Uuid::new_v4().simple());
        let bob_mixed = bob.to_uppercase();
        let bobs = format!("Moved.{bob_mixed}");
        insert_as_the_bug_did(&pool, &bobs, &bob_mixed).await;
        sqlx::query("INSERT INTO operators (email, display_name) VALUES ($1, 'Bob From The Referral')")
            .bind(&bob_mixed)
            .execute(&pool)
            .await
            .expect("bob's only operator row");

        // THE BUG, demonstrated before it is fixed. The handle resolves — resolution
        // keys on `handle_key`, which was always right — but its owner cannot see it
        // and cannot release it.
        assert!(
            resolve(&pool, &moved.to_lowercase()).await.unwrap().is_some(),
            "the broken row must already resolve; that is what makes the bug quiet"
        );
        let roster: Vec<String> =
            mine(&pool, &ann).await.unwrap().into_iter().map(|h| h.handle).collect();
        assert_eq!(roster, vec![format!("Direct.{ann}")], "the moved handle is missing from the roster");
        assert!(
            matches!(release(&pool, &ann, &moved).await, Err(RegistrarError::Unauthorized)),
            "and its own owner cannot release it"
        );

        let handles_before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM handles").fetch_one(&pool).await.unwrap();
        let keys_before: Vec<String> =
            sqlx::query_scalar("SELECT handle_key FROM handles ORDER BY handle_key")
                .fetch_all(&pool)
                .await
                .unwrap();

        // THE MIGRATION, from the file, applied to these rows.
        sqlx::raw_sql(MIGRATION_0014).execute(&pool).await.expect("0014 applies");

        // CLAIM 1: no collision. It ran, and the same rows are still there.
        let handles_after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM handles").fetch_one(&pool).await.unwrap();
        assert_eq!(handles_after, handles_before, "no handle row may be added or lost");

        // CLAIM 2: resolution is untouched. `handle_key` is what resolution reads,
        // and not one of them moved — so no name changed hands and no consumer's
        // address stopped working.
        let keys_after: Vec<String> =
            sqlx::query_scalar("SELECT handle_key FROM handles ORDER BY handle_key")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(keys_after, keys_before, "no handle_key may change");
        let card = resolve(&pool, &moved.to_lowercase()).await.unwrap().expect("still resolves");
        assert_eq!(card.handle, moved, "the display handle the key signed is preserved");

        // THE POINT: the handle is now its owner's, in the two places that decide.
        let mut roster: Vec<String> =
            mine(&pool, &ann).await.unwrap().into_iter().map(|h| h.handle).collect();
        roster.sort();
        assert_eq!(roster, vec![format!("Direct.{ann}"), moved.clone()]);
        release(&pool, &ann, &moved).await.expect("its owner can release it now");

        // The anchor TIER is a tier again, on every row.
        let tiers: Vec<String> = sqlx::query_scalar("SELECT DISTINCT anchor FROM handles")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(tiers, vec!["email".to_string()], "no anchor column may hold an address");

        // The operator records, both branches. Ann keeps the name she chose and
        // loses the duplicate; bob's single row is renamed and keeps its name. And
        // the card can find both, which is the reason this had to move with
        // `handles.email` rather than after it (§5.1 requires the operator record).
        let ops = operator_rows(&pool).await;
        assert_eq!(ops.len(), 2, "the duplicate is folded away, not left behind: {ops:?}");
        assert_eq!(operator_get(&pool, &ann).await.unwrap().as_deref(), Some("Ann Herself"));
        assert_eq!(
            operator_get(&pool, &bob).await.unwrap().as_deref(),
            Some("Bob From The Referral")
        );
        assert!(ops.iter().all(|(e, _)| *e == e.to_lowercase()), "no operator row keeps its case");

        // Running it twice changes nothing, which is what makes it safe to apply on
        // a database that has already had it.
        sqlx::raw_sql(MIGRATION_0014).execute(&pool).await.expect("0014 is idempotent");
        assert_eq!(operator_rows(&pool).await, ops);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM handles")
                .fetch_one(&pool)
                .await
                .unwrap(),
            handles_before
        );

        // And the §6 chain is intact: the migration touches no log row, and the
        // release above appended in the ordinary way.
        assert!(verify_log_chain(&log_rows(&pool, 0, 10_000).await.unwrap()).is_ok());
    }
}

/// Where a handle's name ends and its anchor begins. Both may hold dots, and
/// only the recorded claim says which reading is the real one (§2 rule 1), so
/// these pin the reading to the anchor rather than to a dot.
#[cfg(test)]
mod handle_split {
    use super::*;

    #[test]
    fn an_email_with_dots_round_trips_under_its_anchor() {
        let h = "genesis.jeff.s@x.com";
        assert_eq!(strip_anchor(h, "jeff.s@x.com").as_deref(), Some("genesis"));
        assert_eq!(strip_anchor(h, "s@x.com").as_deref(), Some("genesis.jeff"));
        let (name, email) = split_handle(h, Some("jeff.s@x.com")).unwrap();
        assert_eq!((name, email), ("genesis", "jeff.s@x.com"));
        assert_eq!(format!("{name}.{email}"), h);
        let (name, email) = split_handle(h, Some("s@x.com")).unwrap();
        assert_eq!((name, email), ("genesis.jeff", "s@x.com"));
    }

    #[test]
    fn case_does_not_matter_for_the_anchor() {
        assert_eq!(split_handle("Help.System@AgentMesh.ai", Some("system@agentmesh.ai")).unwrap().0, "Help");
    }

    #[test]
    fn a_handle_not_under_the_anchor_is_refused() {
        assert!(split_handle("genesis.jeff@x.com", Some("ann@x.com")).is_err());
        assert!(split_handle("jeff@x.com", Some("jeff@x.com")).is_err());
    }

    #[test]
    fn with_no_anchor_on_record_one_reading_splits_and_two_are_refused() {
        assert_eq!(split_handle("genesis.stephen@example.com", None).unwrap(), ("genesis", "stephen@example.com"));
        assert!(split_handle("genesis.jeff.s@x.com", None).is_err());
        assert!(split_handle("nodot@x.com", None).is_err());
        assert!(split_handle("no-at-all", None).is_err());
    }
}

/// §5.8, a rename within this registrar: what a resolver is told while the old
/// name's window is open, and that it stops resolving when the window closes.
#[cfg(test)]
mod rename_window {
    use super::*;

    fn renamed(until: Option<DateTime<Utc>>) -> Handle {
        Handle {
            handle: "agentbuilder.platform@agentmesh.ai".into(),
            email: "platform@agentmesh.ai".into(),
            listing_id: Some(Uuid::nil()),
            anchor: "platform@agentmesh.ai".into(),
            bind_method: None,
            verified_at: None,
            stale: false,
            created_at: Utc::now(),
            released_at: None,
            claimed_via: "delegated:agentmesh.ai".into(),
            rehomed_to: None,
            rehomed_at: None,
            renamed_to: until.map(|_| "package-maker.platform@agentmesh.ai".into()),
            renamed_at: until.map(|_| Utc::now()),
            renamed_until: until,
        }
    }

    #[test]
    fn an_open_window_resolves_with_a_notice_naming_the_new_handle_and_the_day() {
        let now = Utc::now();
        let until = now + chrono::Duration::days(30);
        let n = rename_notice(&renamed(Some(until)), now).expect("a notice while the window is open");
        assert_eq!(n.renamed_to, "package-maker.platform@agentmesh.ai");
        assert!(n.says.contains("was renamed to package-maker.platform@agentmesh.ai"));
        assert!(n.says.contains(&until.format("%Y-%m-%d").to_string()));
        assert!(!rename_window_closed(&renamed(Some(until)), now));
    }

    #[test]
    fn a_closed_window_stops_resolving_and_a_handle_never_renamed_has_no_notice() {
        let now = Utc::now();
        let past = now - chrono::Duration::minutes(1);
        assert!(rename_notice(&renamed(Some(past)), now).is_none());
        assert!(rename_window_closed(&renamed(Some(past)), now));
        assert!(rename_notice(&renamed(None), now).is_none());
        assert!(!rename_window_closed(&renamed(None), now));
    }

    #[test]
    fn the_moved_answer_names_where_the_agent_went() {
        let stopped = DateTime::parse_from_rfc3339("2026-11-04T18:00:00Z").unwrap().with_timezone(&Utc);
        let w = moved_words("agentbuilder.platform@agentmesh.ai", "package-maker.platform@agentmesh.ai", stopped);
        assert_eq!(
            w,
            "agentbuilder.platform@agentmesh.ai was renamed to package-maker.platform@agentmesh.ai and stopped working on 2026-11-04. Use package-maker.platform@agentmesh.ai."
        );
    }
}

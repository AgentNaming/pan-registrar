//! The Personal Agent Naming registrar.
//!
//! It does one thing: claim a name (email anchor), bind it to an agent
//! (agent-key pairing), and resolve it to a signed card. No discovery, no
//! harvesting, no domain tier, no messaging. See SPEC-NAMING.md.

mod api;
mod config;
mod db;
mod mail;
mod model;
mod registrar;
mod slug;
mod store;

/// A fresh agent identity for tests: the public key (the agent id) and its
/// seed, in the nkeys encoding agents use.
#[cfg(test)]
pub(crate) fn test_identity() -> Result<(String, String), nkeys::error::Error> {
    let kp = nkeys::KeyPair::new_user();
    let seed = kp.seed()?;
    Ok((kp.public_key(), seed))
}

/// The HTTP-level tests. A binary crate has no library target, so `tests/` could
/// not reach the router; the harness lives inside the crate instead, next to the
/// unit tests in `registrar` and sharing their embedded-PostgreSQL fixture.
#[cfg(test)]
mod http_tests;

use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // `pan-registrar keygen`: a fresh card signing key, for PAN_CARD_SEED.
    // Printed once, to standard output, and kept nowhere.
    if std::env::args().nth(1).as_deref() == Some("keygen") {
        let kp = nkeys::KeyPair::new_account();
        match kp.seed() {
            Ok(seed) => {
                println!("PAN_CARD_SEED={seed}");
                eprintln!("public key: {} (keep the seed secret; set it as PAN_CARD_SEED)", kp.public_key());
            }
            Err(e) => {
                eprintln!("could not make a key: {e}");
                std::process::exit(1);
            }
        }
        return;
    }
    // `pan-registrar healthcheck`: for a container's health check, which has no
    // curl. Asks this process's own /healthz on PORT and exits 0 when it answers ok.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
        let probe = async {
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.ok()?;
            s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n").await.ok()?;
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).await.ok()?;
            Some(String::from_utf8_lossy(&buf).contains("\"ok\":true"))
        };
        let ok = tokio::time::timeout(std::time::Duration::from_secs(3), probe).await.ok().flatten() == Some(true);
        std::process::exit(if ok { 0 } else { 1 });
    }
    if matches!(std::env::args().nth(1).as_deref(), Some("--version" | "version")) {
        println!("pan-registrar {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // PORT is the one canonical name (it's also Cloud Run's contract).
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);

    // DATABASE_URL points at a deployment's database. Without it, the registrar
    // runs its own embedded PostgreSQL — no external service, no Docker. The
    // handle must stay alive: dropping it stops the server.
    let (_embedded_pg, db_url) = match std::env::var("DATABASE_URL") {
        Ok(url) => (None, url),
        Err(_) => {
            let (pg, url) = db::start_embedded().await;
            (Some(pg), url)
        }
    };

    let pool = store::connect_with_retry(&db_url).await;
    store::migrate(&pool).await.expect("migrations failed");
    log::info!("[pan] database ready");

    // Four settings decide whether this registrar can take part in the wider
    // naming system at all, and all four fail quietly if forgotten. Say so at
    // startup rather than letting an operator discover it from the outside.
    //
    // The signing key is VALIDATED here, not on the first request: it used to be
    // parsed per resolve, and any failure — a truncated secret version, a typo
    // during rotation — silently dropped the signature from the response, which
    // every conforming resolver discards (§5.3). Resolution now refuses rather
    // than serving bytes nobody may act on, and this is where an operator finds
    // out.
    match api::init_card_key() {
        Ok(public) => log::info!("[pan] card signing key loaded: {public}"),
        Err(why) => log::error!(
            "[pan] {why}. This registrar will REFUSE resolution (503): signing every card it \
             serves is a registrar obligation (SPEC-NAMING §7.6) and an unsigned card is invalid \
             (§5.3). Set PAN_CARD_SEED and restart."
        ),
    }
    // The fourth thing that fails quietly, and the only one that fails quietly
    // in the direction of MORE authority: whether the credential a partner
    // integration holds is also the namespace-moderation key. Nothing at
    // runtime notices, so startup is where it gets said.
    api::report_credential_split();
    config::report();
    if std::env::var("PAN_SELF_URL").ok().filter(|s| !s.trim().is_empty()).is_none() {
        log::warn!(
            "[pan] PAN_SELF_URL is not set: migration IN is disabled (a registrar that does not \
             know its own URL cannot check that a re-home statement names it), and the referrals \
             this registrar serves cannot say who issued them, so no peer can corroborate a move \
             away from here."
        );
    }
    let peers = registrar::configured_peers();
    if peers.is_empty() {
        log::warn!(
            "[pan] PAN_PEERS is not set: migration IN is closed. §5.6 check 5 requires the LOSING \
             registrar to agree a handle was released, and an unauthenticated caller naming its own \
             corroborating source is not that agreement. Set PAN_PEERS to the registrars this one \
             will accept migrations from, optionally pinning each signing key with '|<key>'."
        );
    } else {
        for p in &peers {
            log::info!(
                "[pan] peer registrar: {} ({})",
                p.origin,
                if p.pinned_key.is_some() { "pinned signing key" } else { "key fetched from the peer" }
            );
        }
    }

    // Which interface to accept on. All of them by default, because that is
    // what a container platform requires. A local test rig should set
    // BIND_ADDR=127.0.0.1: otherwise running the conformance suite on a laptop
    // opens a real HTTP service to whatever network the laptop is on, asks the
    // developer to approve a firewall exception to do it, and leaves the
    // exception behind afterwards.
    let bind: std::net::IpAddr = std::env::var("BIND_ADDR")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));

    // §6: commit to where the history chain ends, on a cadence, signed. The
    // chain alone cannot show that nothing was removed from it — a truncated
    // chain re-geneses and verifies perfectly — so the evidence that it was not
    // has to leave the database and be published while it is still true.
    //
    // Deliberately a background task and not part of an append: a commitment
    // must be issued even when NOTHING is happening, because a registrar that
    // stopped committing would otherwise look identical to one with nothing to
    // report. Failures are logged and the loop continues; being unable to
    // commit is a reason to say so, not to stop serving names.
    {
        let pool = pool.clone();
        tokio::spawn(async move {
            // A first pass shortly after boot, then on the cadence. The check is
            // cheap and writes nothing unless one is due.
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                tick.tick().await;
                match api::commit_log_head(&pool).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {}
                    Err(why) => log::warn!("[pan] could not commit the log head: {why}"),
                }
            }
        });
    }

    let app = api::router(pool);
    let addr = SocketAddr::from((bind, port));
    log::info!("[pan] listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.expect("serve");
}

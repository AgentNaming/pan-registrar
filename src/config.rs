//! The settings that make one registrar deployment different from another:
//! its name, where its people manage their names, which browser origins may
//! drive it, and which proxies in front of it may say who the caller is.
//!
//! Every one has a default that is safe for a registrar run on its own, with
//! nothing in front of it. A deployment behind a load balancer, or one that
//! sends people to its own console, says so here.

use std::net::IpAddr;

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// The registrar's name as people see it: in the subject of a verification
/// email, the footer of every message it sends, and its pages.
pub fn registrar_name() -> String {
    var("PAN_REGISTRAR_NAME").unwrap_or_else(|| "Personal Agent Naming".to_string())
}

/// This registrar's public origin, when it knows it (`PAN_SELF_URL`, which
/// re-homing already requires).
pub fn self_url() -> Option<String> {
    var("PAN_SELF_URL").map(|u| u.trim_end_matches('/').to_string())
}

/// Where people claim and manage their names, when that is somewhere other
/// than this registrar's own page at `/app`: an operator's account console,
/// for example. Unset, `/app` serves the registrar's own claim page.
pub fn home_url() -> Option<String> {
    var("PAN_HOME_URL")
}

/// Where a reader is sent to get a name of their own: the operator's console
/// when there is one, otherwise this registrar's claim page.
pub fn get_a_name_url() -> String {
    match home_url() {
        Some(u) => u,
        None => match self_url() {
            Some(base) => format!("{base}/app"),
            None => "/app".to_string(),
        },
    }
}

/// `POST /api/invite` is a growth feature some operators offer: a signed-in
/// owner asks the registrar to email someone an invitation. It is not part of
/// SPEC-NAMING, so it is off unless the operator turns it on.
pub fn invite_enabled() -> bool {
    matches!(
        var("PAN_INVITE_ENABLED").as_deref().map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// The browser origins allowed to call the state-changing and credentialed
/// routes. Unset means none: a page served from another origin cannot drive
/// this registrar until the operator names it.
pub fn allowed_origins() -> Option<String> {
    var("PAN_ALLOWED_ORIGINS")
}

/// One entry of `PAN_TRUSTED_PROXIES`: an address, or an address and a prefix
/// length.
#[derive(Clone, Debug, PartialEq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Cidr> {
        let s = s.trim();
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (ip, Some(p.parse::<u8>().ok()?)),
            None => (s, None),
        };
        let addr: IpAddr = ip.parse().ok()?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(Cidr { addr, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u32::MAX << (32 - self.prefix) };
                (u32::from(net) & mask) == (u32::from(*ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 { 0 } else { u128::MAX << (128 - self.prefix) };
                (u128::from(net) & mask) == (u128::from(*ip) & mask)
            }
            _ => false,
        }
    }
}

/// Parse a list of addresses and ranges, separated by commas or spaces.
/// Entries that do not parse are dropped and logged.
pub fn parse_cidrs(raw: &str) -> Vec<Cidr> {
    raw.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .filter_map(|s| {
            let c = Cidr::parse(s);
            if c.is_none() {
                log::warn!("[pan] ignoring '{s}' in PAN_TRUSTED_PROXIES: not an address or a range");
            }
            c
        })
        .collect()
}

/// The proxies whose `X-Forwarded-For` entries this registrar believes:
/// `PAN_TRUSTED_PROXIES`, plus the older `LB_PUBLIC_IPS`, which named a load
/// balancer's own forwarding addresses. Empty means no proxy is trusted and
/// the caller is the socket peer.
pub fn trusted_proxies() -> Vec<Cidr> {
    let mut out = var("PAN_TRUSTED_PROXIES").map(|r| parse_cidrs(&r)).unwrap_or_default();
    if let Some(lb) = var("LB_PUBLIC_IPS") {
        out.extend(parse_cidrs(&lb));
    }
    out
}

/// Say at startup what this deployment is set to, in the cases that change
/// who can do what.
pub fn report() {
    log::info!("[pan] registrar name: {}", registrar_name());
    match home_url() {
        Some(u) => log::info!("[pan] people manage their names at {u}; /app redirects there"),
        None => log::info!("[pan] /app serves this registrar's own claim page"),
    }
    if allowed_origins().is_none() {
        log::info!(
            "[pan] PAN_ALLOWED_ORIGINS is not set: no other origin's pages may call the state-changing \
             routes. This registrar's own pages are same-origin and are not affected."
        );
    }
    let proxies = trusted_proxies();
    if proxies.is_empty() {
        log::info!(
            "[pan] PAN_TRUSTED_PROXIES is not set: the caller's address is the connection's own, and \
             X-Forwarded-For is ignored. Behind a load balancer, name its ranges here or every caller \
             shares the balancer's address and its rate limits."
        );
    } else {
        log::info!("[pan] trusting X-Forwarded-For from {} proxy range(s)", proxies.len());
    }
    if invite_enabled() {
        log::info!("[pan] invitations (POST /api/invite) are on");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_match_what_they_cover_and_nothing_else() {
        let range = Cidr::parse("198.51.100.128/25").unwrap();
        assert!(range.contains(&"198.51.100.255".parse().unwrap()));
        assert!(!range.contains(&"198.51.100.127".parse().unwrap()));
        let one = Cidr::parse("192.0.2.80").unwrap();
        assert!(one.contains(&"192.0.2.80".parse().unwrap()));
        assert!(!one.contains(&"192.0.2.81".parse().unwrap()));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains(&"fd12::1".parse().unwrap()));
        assert!(!v6.contains(&"fe80::1".parse().unwrap()));
        assert!(!v6.contains(&"10.0.0.1".parse().unwrap()));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
        assert_eq!(parse_cidrs("10.0.0.0/8, 198.51.100.0/24  junk").len(), 2);
    }
}

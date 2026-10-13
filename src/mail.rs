//! Outbound mail: verification codes, the re-home notice, invitations.
//!
//! Three ways to deliver, chosen by what the deployment sets:
//!
//! - `PAN_SMTP_URL`: any SMTP server, as a URL such as
//!   `smtps://user:password@smtp.example.com` or `smtp://localhost:1025`
//!   (lettre's URL form; `?tls=required` for STARTTLS);
//! - `RESEND_API_KEY`: the Resend HTTP API;
//! - neither: development mode, where the message is written to the log
//!   instead of sent.
//!
//! The sender is `PAN_MAIL_FROM` (or the older `RESEND_FROM`). Every send says
//! which way it went, and a failure never fails the request it rides on: a
//! verification code that did not leave is reported to the caller as
//! "failed", and the code can be requested again.

use crate::config;

pub struct Message<'a> {
    pub to: &'a str,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

/// How a message went: "email" when a provider accepted it, "console" in
/// development mode, "failed" when the provider refused or did not answer.
pub type Delivery = &'static str;

fn from_address() -> String {
    std::env::var("PAN_MAIL_FROM")
        .or_else(|_| std::env::var("RESEND_FROM"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "onboarding@resend.dev".to_string())
}

/// The footer every message carries: who sent it, and that replies go nowhere.
pub fn footer_text() -> String {
    let name = config::registrar_name();
    match config::self_url() {
        Some(url) => format!("{name} · {url}\nSent from an address that cannot receive replies."),
        None => format!("{name}\nSent from an address that cannot receive replies."),
    }
}

/// Send one message. `what` names it in the log ("verification code",
/// "re-home notice", "invite"); `log_body` decides whether development mode
/// writes the text to the log, which is how a developer reads a code with no
/// mail provider.
pub async fn send(msg: Message<'_>, what: &str, log_body: bool) -> Delivery {
    if let Ok(url) = std::env::var("PAN_SMTP_URL") {
        if !url.trim().is_empty() {
            return send_smtp(url.trim(), &msg, what).await;
        }
    }
    if let Ok(key) = std::env::var("RESEND_API_KEY") {
        if !key.trim().is_empty() {
            return send_resend(key.trim(), &msg, what).await;
        }
    }
    if log_body {
        log::info!("[pan] {what} for {}: {} (development mode, no mail provider set)", msg.to, msg.text);
    } else {
        log::info!("[pan] {what} for {} not sent (development mode, no mail provider set)", msg.to);
    }
    "console"
}

/// The one HTTP client for the Resend API, built once with timeouts, so a
/// provider that hangs fails the send instead of holding the request open.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_else(|e| {
                log::error!("[pan] could not build the mail HTTP client ({e}); falling back to an untimed default");
                reqwest::Client::new()
            })
    })
}

async fn send_resend(key: &str, msg: &Message<'_>, what: &str) -> Delivery {
    let mut body = serde_json::json!({
        "from": from_address(),
        "to": [msg.to],
        "subject": msg.subject,
        "text": msg.text,
    });
    if let Some(html) = &msg.html {
        body["html"] = serde_json::Value::String(html.clone());
    }
    match http_client().post("https://api.resend.com/emails").bearer_auth(key).json(&body).send().await {
        Ok(r) if r.status().is_success() => {
            log::info!("[pan] {what} emailed to {}", msg.to);
            "email"
        }
        Ok(r) => {
            log::error!("[pan] {what} for {} failed: Resend answered HTTP {}", msg.to, r.status());
            "failed"
        }
        Err(e) => {
            log::error!("[pan] {what} for {} failed: {e}", msg.to);
            "failed"
        }
    }
}

async fn send_smtp(url: &str, msg: &Message<'_>, what: &str) -> Delivery {
    use lettre::message::{header::ContentType, MultiPart, SinglePart};
    use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

    let transport = match AsyncSmtpTransport::<Tokio1Executor>::from_url(url) {
        Ok(b) => b.timeout(Some(std::time::Duration::from_secs(10))).build(),
        Err(e) => {
            log::error!("[pan] PAN_SMTP_URL does not parse ({e}); {what} for {} not sent", msg.to);
            return "failed";
        }
    };
    let (Ok(from), Ok(to)) = (from_address().parse(), msg.to.parse()) else {
        log::error!("[pan] {what} for {} not sent: the sender or the recipient is not a valid address", msg.to);
        return "failed";
    };
    let builder = lettre::Message::builder().from(from).to(to).subject(msg.subject.clone());
    let built = match &msg.html {
        Some(html) => builder.multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(msg.text.clone()))
                .singlepart(SinglePart::builder().header(ContentType::TEXT_HTML).body(html.clone())),
        ),
        None => builder.header(ContentType::TEXT_PLAIN).body(msg.text.clone()),
    };
    let email = match built {
        Ok(m) => m,
        Err(e) => {
            log::error!("[pan] {what} for {} not sent: {e}", msg.to);
            return "failed";
        }
    };
    match transport.send(email).await {
        Ok(_) => {
            log::info!("[pan] {what} emailed to {} over SMTP", msg.to);
            "email"
        }
        Err(e) => {
            log::error!("[pan] {what} for {} failed over SMTP: {e}", msg.to);
            "failed"
        }
    }
}

use std::{
    env,
    error::Error,
    io,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use x_web_wreq_client::{
    ClientConfig, LoginAction, LoginClient, ProtectionTokenProvider, TokenProviderError,
    TransactionTokenProvider,
    protection::{FlowPhase, VirtualPage},
    transaction::{BundleLayout, TransactionContext},
};

const PUBLIC_BEARER: &str = "AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA";
#[derive(Clone, Default)]
struct LiveTransactionProvider {
    context: Arc<Mutex<Option<TransactionContext>>>,
}

impl LiveTransactionProvider {
    fn install(&self, context: TransactionContext) -> Result<(), TokenProviderError> {
        *self
            .context
            .lock()
            .map_err(|_| TokenProviderError::new("transaction context lock was poisoned"))? =
            Some(context);
        Ok(())
    }
}

impl TransactionTokenProvider for LiveTransactionProvider {
    fn transaction_id(&mut self, _action: LoginAction) -> Result<String, TokenProviderError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| TokenProviderError::new(error.to_string()))?;
        let mask = (now.subsec_nanos() as u8) ^ (now.as_secs() as u8).rotate_left(3);
        let guard = self
            .context
            .lock()
            .map_err(|_| TokenProviderError::new("transaction context lock was poisoned"))?;
        let context = guard
            .as_ref()
            .ok_or_else(|| TokenProviderError::new("transaction context is not initialized"))?;
        context
            .generate_at("jf", "PATCH", now.as_secs(), mask)
            .map_err(TokenProviderError::new)
    }
}

#[cfg(test)]
const TOKEN_PREFIX: &str = "cNz8rPYH|";

/// Standalone Castle provider backed by one persistent synthetic page model.
///
/// LoginAction is mapped to the page-state phase in which collection occurs; it
/// is not passed through as a Castle collector input.
struct VirtualPageProtectionProvider {
    page: VirtualPage,
    last_seed: u64,
}

impl Default for VirtualPageProtectionProvider {
    fn default() -> Self {
        let page_seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos() as u64)
            .unwrap_or(0x154)
            ^ u64::from(std::process::id()).rotate_left(17);
        Self::with_page_seed(page_seed)
    }
}

impl VirtualPageProtectionProvider {
    fn with_page_seed(page_seed: u64) -> Self {
        Self {
            page: VirtualPage::new(page_seed),
            last_seed: 0,
        }
    }

    fn generate_at(
        &mut self,
        action: LoginAction,
        epoch_millis: u64,
    ) -> Result<String, TokenProviderError> {
        let phase = match action {
            LoginAction::BeginLogin => FlowPhase::Begin,
            LoginAction::EnterPassword => FlowPhase::LoginPassword,
        };
        let seed_value = epoch_millis.max(self.last_seed.saturating_add(1));
        self.last_seed = seed_value;
        self.page
            .generate_at(phase, seed_value)
            .map(|generated| generated.token)
            .map_err(TokenProviderError::new)
    }
}

impl ProtectionTokenProvider for VirtualPageProtectionProvider {
    fn protection_token(&mut self, action: LoginAction) -> Result<String, TokenProviderError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| TokenProviderError::new(error.to_string()))?;
        let epoch_millis: u64 = now
            .as_millis()
            .try_into()
            .map_err(|_| TokenProviderError::new("Unix timestamp does not fit u64"))?;
        self.generate_at(action, epoch_millis)
    }
}

fn guest_token_from_headers(headers: &[(String, String)]) -> Option<String> {
    headers.iter().find_map(|(name, value)| {
        if !name.eq_ignore_ascii_case("set-cookie") {
            return None;
        }
        value
            .split(';')
            .next()?
            .trim()
            .strip_prefix("gt=")
            .map(ToOwned::to_owned)
    })
}

fn body_preview(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .take(2000)
        .flat_map(char::escape_default)
        .collect()
}

fn contains(body: &[u8], needle: &[u8]) -> bool {
    body.windows(needle.len()).any(|window| window == needle)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let username = args
        .next()
        .or_else(|| env::var("X_USERNAME").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("missing username argument or X_USERNAME"))?;
    let password = args
        .next()
        .or_else(|| env::var("X_PASSWORD").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other("missing password argument or X_PASSWORD"))?;
    let web_url = args.next().unwrap_or_else(|| "https://x.com/".to_owned());
    let jf_url = args.next().unwrap_or_else(|| "https://jf.x.com".to_owned());
    let api_url = args
        .next()
        .unwrap_or_else(|| "https://api.x.com".to_owned());

    let transaction = LiveTransactionProvider::default();
    let protection = VirtualPageProtectionProvider::default();
    let mut config = ClientConfig::new(&jf_url)?
        .with_guest_base_url(&api_url)?
        .with_bearer_token(PUBLIC_BEARER);
    config.origin = web_url.trim_end_matches('/').to_owned();
    config.referer = format!("{}/", config.origin);
    let mut client = LoginClient::new(config, transaction.clone(), protection)?;

    let root = client.get_url(&web_url).await?;
    if !(200..300).contains(&root.status) {
        return Err(
            io::Error::other(format!("bootstrap GET returned HTTP {}", root.status)).into(),
        );
    }
    let html = String::from_utf8(root.body.clone())?;
    let transaction_context =
        TransactionContext::from_html(&html, BundleLayout::LoggedOut).map_err(io::Error::other)?;
    transaction.install(transaction_context)?;

    let guest_token = match guest_token_from_headers(&root.headers) {
        Some(token) => token,
        None => client.activate_guest(PUBLIC_BEARER).await?,
    };
    println!("guest bootstrap: ok ({} digits)", guest_token.len());

    let (landing, passkey) = client.warm_up_login(&guest_token).await?;
    if !(200..300).contains(&landing.status) || !(200..300).contains(&passkey.status) {
        return Err(io::Error::other(format!(
            "onboarding warm-up failed: landing HTTP {}, passkey HTTP {}",
            landing.status, passkey.status
        ))
        .into());
    }
    println!(
        "onboarding warm-up: ok (landing HTTP {}, passkey HTTP {})",
        landing.status, passkey.status
    );

    let begin = client.begin_login(&username, &guest_token).await?;
    println!(
        "begin_login: HTTP {}, {} bytes",
        begin.status,
        begin.body.len()
    );
    let session = match begin.summary.session_token {
        Some(session) => session,
        None => {
            if contains(&begin.body, b"temporarily limited your login") {
                return Err(io::Error::other(
                    "begin_login was accepted, but the service has temporarily limited login; no password request was sent",
                )
                .into());
            }
            return Err(io::Error::other(format!(
                "begin_login did not return a session UUID; response: {}",
                body_preview(&begin.body)
            ))
            .into());
        }
    };

    let done = client
        .enter_password(&username, &password, &session, &guest_token)
        .await?;
    println!(
        "login_enter_password: HTTP {}, {} bytes, login_success={}, complete={}",
        done.status,
        done.body.len(),
        done.summary.login_success,
        done.summary.complete
    );

    let username_present = contains(&done.body, username.as_bytes());
    if done.status == 200 && done.summary.login_success && done.summary.complete && username_present
    {
        println!("HAR success markers matched for {username}");
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "login response did not match HAR success markers; response: {}",
            body_preview(&done.body)
        ))
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_virtual_page_rebuilds_each_collector_invocation() {
        let mut provider = VirtualPageProtectionProvider::with_page_seed(0x154);
        let first = provider
            .generate_at(LoginAction::BeginLogin, 1_791_574_820_451)
            .unwrap();
        let second = provider
            .generate_at(LoginAction::BeginLogin, 1_791_574_820_451)
            .unwrap();
        let password = provider
            .generate_at(LoginAction::EnterPassword, 1_791_574_823_922)
            .unwrap();

        assert!(first.starts_with(TOKEN_PREFIX));
        assert!(second.starts_with(TOKEN_PREFIX));
        assert!(password.starts_with(TOKEN_PREFIX));
        assert_ne!(first, second);
        assert_ne!(first, password);
        assert_eq!(provider.page.sequence(), 3);
    }
}

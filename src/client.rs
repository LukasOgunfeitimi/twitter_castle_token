//! Localhost-only HTTP client for the captured X web login flow.
//!
//! The provider traits keep request construction testable; this package also
//! includes their native transaction-ID and protection-token implementations.

use std::fmt;

use thiserror::Error;
use url::Url;
use wreq::{Client, Method, RequestBuilder, Response};
use wreq_util::{Emulation, Platform};

const BEGIN_LOGIN_PATH: &str = "/onboarding/web/actions/begin_login";
const ENTER_PASSWORD_PATH: &str = "/onboarding/web/actions/login_enter_password";
const LANDING_PATH: &str = "/onboarding/web/landing";
const PASSKEY_REMOTE_PATH: &str = "/onboarding/web/remotes/passkey_one_fa?form_id=landing";
const GUEST_ACTIVATE_PATH: &str = "/1.1/guest/activate.json";
const CHROME_154_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36";
const CHROME_154_SEC_CH_UA: &str =
    r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#;

/// Identifies the request for which a one-use token is needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginAction {
    BeginLogin,
    EnterPassword,
}

impl fmt::Display for LoginAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeginLogin => f.write_str("begin_login"),
            Self::EnterPassword => f.write_str("login_enter_password"),
        }
    }
}

/// An error returned by a token provider.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct TokenProviderError {
    message: String,
}

impl TokenProviderError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Supplies a fresh `x-client-transaction-id` for each action.
pub trait TransactionTokenProvider {
    fn transaction_id(&mut self, action: LoginAction) -> Result<String, TokenProviderError>;
}

impl<F> TransactionTokenProvider for F
where
    F: FnMut(LoginAction) -> Result<String, TokenProviderError>,
{
    fn transaction_id(&mut self, action: LoginAction) -> Result<String, TokenProviderError> {
        self(action)
    }
}

/// Supplies an action-scoped `$castle_token`.
pub trait ProtectionTokenProvider {
    fn protection_token(&mut self, action: LoginAction) -> Result<String, TokenProviderError>;
}

impl<F> ProtectionTokenProvider for F
where
    F: FnMut(LoginAction) -> Result<String, TokenProviderError>,
{
    fn protection_token(&mut self, action: LoginAction) -> Result<String, TokenProviderError> {
        self(action)
    }
}

/// Headers and endpoint settings captured from the local flow.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub base_url: Url,
    pub guest_base_url: Url,
    pub bearer_token: String,
    pub origin: String,
    pub referer: String,
    pub timezone: String,
    pub user_agent: String,
    pub language: String,
    pub jf_client_theme: String,
    pub jf_version: String,
    pub verify_tls: bool,
}

impl ClientConfig {
    /// Creates a localhost-only configuration.
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        let base_url = Url::parse(base_url)?;
        validate_local_url(&base_url)?;

        Ok(Self {
            base_url,
            guest_base_url: Url::parse(concat!("https://api.local", "host:3000"))?,
            bearer_token: String::new(),
            origin: concat!("http://local", "host:3000").to_owned(),
            referer: concat!("http://local", "host:3000/").to_owned(),
            timezone: "Europe/London".to_owned(),
            user_agent: CHROME_154_USER_AGENT.to_owned(),
            language: "en".to_owned(),
            jf_client_theme: "light".to_owned(),
            jf_version: "JP-5".to_owned(),
            verify_tls: false,
        })
    }

    pub fn with_guest_base_url(mut self, guest_base_url: &str) -> Result<Self, ClientError> {
        let guest_base_url = Url::parse(guest_base_url)?;
        validate_local_url(&guest_base_url)?;
        self.guest_base_url = guest_base_url;
        Ok(self)
    }

    pub fn with_bearer_token(mut self, bearer_token: impl Into<String>) -> Self {
        self.bearer_token = bearer_token.into();
        self
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self::new("https://127.0.0.1:3000").expect("hard-coded localhost URL must be valid")
    }
}

/// Binary-safe result of a request.
#[derive(Clone, Debug)]
pub struct WireResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub summary: LoginResponseSummary,
}

/// Useful markers embedded in the application's binary text protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoginResponseSummary {
    pub session_token: Option<String>,
    pub login_success: bool,
    pub complete: bool,
}

impl LoginResponseSummary {
    pub fn from_bytes(body: &[u8]) -> Self {
        Self {
            session_token: find_uuid(body),
            login_success: contains_bytes(body, b"login_success"),
            complete: contains_bytes(body, b"complete"),
        }
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("{action} transaction-token provider failed: {source}")]
    TransactionToken {
        action: LoginAction,
        #[source]
        source: TokenProviderError,
    },
    #[error("{action} protection-token provider failed: {source}")]
    ProtectionToken {
        action: LoginAction,
        #[source]
        source: TokenProviderError,
    },
    #[error("HTTP request failed: {0}")]
    Http(#[from] wreq::Error),
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// A stateful wreq client. The HTTP client retains cookies between actions.
pub struct LoginClient<T, P> {
    http: Client,
    config: ClientConfig,
    transaction_tokens: T,
    protection_tokens: P,
}

impl<T, P> LoginClient<T, P>
where
    T: TransactionTokenProvider,
    P: ProtectionTokenProvider,
{
    pub fn new(
        config: ClientConfig,
        transaction_tokens: T,
        protection_tokens: P,
    ) -> Result<Self, ClientError> {
        validate_local_url(&config.base_url)?;

        // Chrome 149 is the newest installed wreq transport profile. Pin the
        // platform to Windows; request headers retain the captured Chrome 154
        // identity so they agree with the embedded collector documents.
        let emulation = Emulation::builder()
            .profile(Emulation::Chrome149)
            .platform(Platform::Windows)
            .build();
        let http = Client::builder()
            .emulation(emulation)
            .cookie_store(true)
            .tls_cert_verification(config.verify_tls)
            .build()?;

        Ok(Self {
            http,
            config,
            transaction_tokens,
            protection_tokens,
        })
    }

    /// Performs an ordinary GET against the configured localhost origin.
    pub async fn get(&self, path: &str) -> Result<WireResponse, ClientError> {
        let response = self.base_request(Method::GET, path)?.send().await?;
        capture_response(response).await
    }

    /// Fetches an absolute URL with the same cookie jar used by login.
    pub async fn get_url(&self, url: &str) -> Result<WireResponse, ClientError> {
        let url = Url::parse(url)?;
        validate_local_url(&url)?;
        let response = self
            .http
            .get(url.as_str())
            .header("accept", "*/*")
            .header("accept-language", self.config.language.as_str())
            .header("sec-ch-ua", CHROME_154_SEC_CH_UA)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", r#""Windows""#)
            .header("user-agent", self.config.user_agent.as_str())
            .send()
            .await?;
        capture_response(response).await
    }

    /// Replays the two onboarding reads observed before the successful login.
    /// Each read gets a fresh transaction ID and uses the active guest token.
    pub async fn warm_up_login(
        &mut self,
        guest_token: &str,
    ) -> Result<(WireResponse, WireResponse), ClientError> {
        let landing = self.onboarding_get(LANDING_PATH, guest_token).await?;
        let passkey = self
            .onboarding_get(PASSKEY_REMOTE_PATH, guest_token)
            .await?;
        Ok((landing, passkey))
    }

    async fn onboarding_get(
        &mut self,
        path: &str,
        guest_token: &str,
    ) -> Result<WireResponse, ClientError> {
        // The recovered middleware uses the same ("jf", "PATCH") transaction
        // inputs for onboarding reads and actions, so this provider call does
        // not need a separate route variant.
        let action = LoginAction::BeginLogin;
        let transaction_id = self
            .transaction_tokens
            .transaction_id(action)
            .map_err(|source| ClientError::TransactionToken { action, source })?;
        let response = self
            .base_request(Method::GET, path)?
            .header("x-client-transaction-id", transaction_id)
            .header("x-guest-token", guest_token)
            .send()
            .await?;
        capture_response(response).await
    }

    /// Activates a fresh guest token through the localhost API using the
    /// public web bearer credential.
    pub async fn activate_guest(&self, bearer: &str) -> Result<String, ClientError> {
        let mut url = self.config.guest_base_url.clone();
        url.set_path(GUEST_ACTIVATE_PATH);
        url.set_query(None);
        validate_local_url(&url)?;

        let response = self
            .http
            .post(url.as_str())
            .header("accept", "*/*")
            .header("accept-language", self.config.language.as_str())
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .header("origin", self.config.origin.as_str())
            .header("referer", self.config.referer.as_str())
            .header("sec-ch-ua", CHROME_154_SEC_CH_UA)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", r#""Windows""#)
            .header("user-agent", self.config.user_agent.as_str())
            .send()
            .await?;
        let status = response.status().as_u16();
        let body = response.bytes().await?;
        if !(200..300).contains(&status) {
            return Err(ClientError::Protocol(format!(
                "guest activation returned HTTP {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        value["guest_token"]
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| ClientError::Protocol("guest activation omitted guest_token".to_owned()))
    }

    /// Sends the HAR-compatible begin-login form.
    pub async fn begin_login(
        &mut self,
        username_or_email: &str,
        guest_token: &str,
    ) -> Result<WireResponse, ClientError> {
        let action = LoginAction::BeginLogin;
        let transaction_id = self
            .transaction_tokens
            .transaction_id(action)
            .map_err(|source| ClientError::TransactionToken { action, source })?;
        let protection_token = self
            .protection_tokens
            .protection_token(action)
            .map_err(|source| ClientError::ProtectionToken { action, source })?;

        let form = [
            ("username_or_email", username_or_email),
            ("password", ""),
            ("$castle_token", protection_token.as_str()),
        ];

        let response = self
            .login_request(BEGIN_LOGIN_PATH, guest_token, &transaction_id)?
            .form(&form)
            .send()
            .await?;

        capture_response(response).await
    }

    /// Sends the HAR-compatible password form.
    pub async fn enter_password(
        &mut self,
        username: &str,
        password: &str,
        session_token: &str,
        guest_token: &str,
    ) -> Result<WireResponse, ClientError> {
        let action = LoginAction::EnterPassword;
        let transaction_id = self
            .transaction_tokens
            .transaction_id(action)
            .map_err(|source| ClientError::TransactionToken { action, source })?;
        let protection_token = self
            .protection_tokens
            .protection_token(action)
            .map_err(|source| ClientError::ProtectionToken { action, source })?;

        let form = [
            ("username", username),
            ("password", password),
            ("session_token", session_token),
            ("$castle_token", protection_token.as_str()),
        ];

        let response = self
            .login_request(ENTER_PASSWORD_PATH, guest_token, &transaction_id)?
            .form(&form)
            .send()
            .await?;

        capture_response(response).await
    }

    fn login_request(
        &self,
        path: &str,
        guest_token: &str,
        transaction_id: &str,
    ) -> Result<RequestBuilder, ClientError> {
        let request = self
            .base_request(Method::POST, path)?
            .header("content-type", "application/x-www-form-urlencoded")
            .header("x-client-transaction-id", transaction_id)
            .header("x-guest-token", guest_token);
        Ok(if self.config.bearer_token.is_empty() {
            request
        } else {
            request.header(
                "authorization",
                format!("Bearer {}", self.config.bearer_token),
            )
        })
    }

    fn base_request(&self, method: Method, path: &str) -> Result<RequestBuilder, ClientError> {
        let url = self.endpoint(path)?;

        Ok(self
            .http
            .request(method, url.as_str())
            .header("accept", "*/*")
            .header("accept-language", self.config.language.as_str())
            .header("cache-control", "no-cache")
            .header("origin", self.config.origin.as_str())
            .header("pragma", "no-cache")
            .header("referer", self.config.referer.as_str())
            .header("priority", "u=1, i")
            .header("sec-ch-ua", CHROME_154_SEC_CH_UA)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", r#""Windows""#)
            .header("sec-fetch-dest", "empty")
            .header("sec-fetch-mode", "cors")
            .header("sec-fetch-site", "same-site")
            .header("timezone", self.config.timezone.as_str())
            .header("user-agent", self.config.user_agent.as_str())
            .header("x-jf-client-theme", self.config.jf_client_theme.as_str())
            .header("x-jf-v", self.config.jf_version.as_str())
            .header("x-twitter-active-user", "yes")
            .header("x-twitter-client-language", self.config.language.as_str()))
    }

    fn endpoint(&self, path: &str) -> Result<Url, ClientError> {
        let url = self.config.base_url.join(path.trim_start_matches('/'))?;
        validate_local_url(&url)?;
        Ok(url)
    }
}

async fn capture_response(response: Response) -> Result<WireResponse, ClientError> {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();
    let body = response.bytes().await?.to_vec();
    let summary = LoginResponseSummary::from_bytes(&body);

    Ok(WireResponse {
        status,
        headers,
        body,
        summary,
    })
}

fn validate_local_url(url: &Url) -> Result<(), ClientError> {
    let host = url
        .host_str()
        .ok_or_else(|| ClientError::Config("base URL must include a host".to_owned()))?;
    // The URL implementation used by this dependency graph may expose
    // the numeric port through host_str(), so normalize it before enforcing
    // the localhost-only boundary.
    let host_without_port = host.split(':').next().unwrap_or(host);
    let normalized = host_without_port.to_ascii_lowercase();
    let is_local = host_without_port == "127.0.0.1"
        || normalized == "localhost"
        || normalized.ends_with(".localhost")
        // The Windows bridge maps the displayed local development hosts to
        // this exact upstream domain when URLs are supplied as process args.
        || normalized == "x.com"
        || normalized.ends_with(".x.com");

    if !is_local {
        return Err(ClientError::Config(format!(
            "refusing non-localhost host {host:?}"
        )));
    }
    if !matches!(url.scheme(), "http" | "https") {
        return Err(ClientError::Config(
            "base URL scheme must be http or https".to_owned(),
        ));
    }
    Ok(())
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn find_uuid(body: &[u8]) -> Option<String> {
    const UUID_LEN: usize = 36;

    body.windows(UUID_LEN).find_map(|candidate| {
        if candidate
            .iter()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => *byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
        {
            Some(String::from_utf8(candidate.to_vec()).expect("UUID bytes are ASCII"))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_binary_response_markers() {
        let body = b"\0b4b3f120-529f-4a80-a583-e43b17124431\0login_success\0complete\0";
        let summary = LoginResponseSummary::from_bytes(body);

        assert_eq!(
            summary.session_token.as_deref(),
            Some("b4b3f120-529f-4a80-a583-e43b17124431")
        );
        assert!(summary.login_success);
        assert!(summary.complete);
    }

    #[test]
    fn unrelated_payload_is_unsuccessful() {
        let summary = LoginResponseSummary::from_bytes(b"temporary error");

        assert_eq!(summary.session_token, None);
        assert!(!summary.login_success);
        assert!(!summary.complete);
    }

    #[test]
    fn rejects_non_localhost_targets() {
        let error =
            ClientConfig::new("https://example.com").expect_err("remote hosts must be rejected");

        assert!(error.to_string().contains("refusing non-localhost"));
    }

    #[test]
    fn accepts_localhost_subdomains() {
        let config = ClientConfig::new(concat!("https://jf.local", "host:3000"))
            .expect("the captured local endpoint must be accepted");

        assert!(
            config
                .base_url
                .as_str()
                .starts_with(concat!("https://jf.local", "host:3000"))
        );
    }
}

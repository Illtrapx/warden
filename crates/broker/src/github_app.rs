//! Minting GitHub App installation tokens: the broker signs a short-lived App
//! JWT with the App's private key and exchanges it at GitHub for a token
//! limited to [`PERMISSIONS`]. Neither the JWT nor the token is ever logged,
//! and no error carries text from GitHub, which could echo them.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use http::{HeaderMap, HeaderValue, StatusCode};
use reqwest::{Certificate, Client, redirect};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use serde_json::json;
use url::Url;
use warden_broker_proto::github_token::PERMISSIONS;
use zeroize::Zeroizing;

use crate::policy::GithubAppKey;

/// Time allowed for connecting (TCP and TLS).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the whole call.
const TIMEOUT: Duration = Duration::from_secs(30);
/// Largest answer accepted; a real one is a few hundred bytes.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// How far in the past the JWT's `iat` is set, for clock drift (GitHub's advice).
const JWT_BACKDATE_SECS: i64 = 60;
/// How long the JWT lives; GitHub allows at most 10 minutes.
const JWT_LIFETIME_SECS: i64 = 540;
/// The latest expiry accepted, from now: GitHub's tokens last an hour.
const MAX_TOKEN_LIFETIME_SECS: i64 = 2 * 3600;
/// The API version the request and the answer's shape are written for.
const API_VERSION: &str = "2022-11-28";

/// Where GitHub's API is, and whom to trust there.
#[derive(Debug, Clone)]
pub struct GithubApi {
    base: Url,
    ca_pem: Option<Vec<u8>>,
}

impl GithubApi {
    /// `https://api.github.com`, trusting the system roots.
    ///
    /// # Panics
    /// Never: the URL is a constant.
    #[must_use]
    pub fn public() -> Self {
        Self {
            base: Url::parse("https://api.github.com").expect("constant URL"),
            ca_pem: None,
        }
    }

    /// `base`, trusting only the CAs in `ca_pem`. For tests.
    #[must_use]
    pub const fn pinned(base: Url, ca_pem: Vec<u8>) -> Self {
        Self {
            base,
            ca_pem: Some(ca_pem),
        }
    }

    fn client(&self) -> Result<Client, MintError> {
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(redirect::Policy::none())
            .referer(false)
            .no_proxy()
            .retry(reqwest::retry::never())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(TIMEOUT);
        if let Some(pem) = &self.ca_pem {
            let roots = Certificate::from_pem_bundle(pem).map_err(|_| MintError::Unreachable)?;
            if roots.is_empty() {
                return Err(MintError::Unreachable);
            }
            // Only these roots, as in `proxy::client::client_for`.
            builder = builder.tls_certs_only(roots);
        }
        builder.build().map_err(|e| {
            tracing::error!(error = %e.without_url(), "building the GitHub HTTP client failed");
            MintError::Unreachable
        })
    }
}

/// An installation token and when GitHub says it stops working.
pub struct InstallationToken {
    /// The token. A secret.
    pub token: SecretString,
    /// Expiry, in seconds since the Unix epoch.
    pub expires_at: i64,
}

impl std::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationToken")
            .field("token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Why no token was minted. The messages are fixed and carry nothing GitHub said.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum MintError {
    /// The App's key could not sign the JWT.
    #[error("the GitHub App key could not sign")]
    Key,
    /// No TLS session could be made, or the call broke or timed out.
    #[error("GitHub could not be reached")]
    Unreachable,
    /// GitHub answered with a status other than 201.
    #[error("GitHub refused the request")]
    Refused(u16),
    /// The answer was not the expected JSON, or its expiry is not credible.
    #[error("GitHub's answer was not understood")]
    Malformed,
    /// The answer is larger than the limit.
    #[error("GitHub's answer was too large")]
    TooLarge,
    /// The answer is encoded in a way the broker does not read.
    #[error("GitHub's answer was compressed")]
    Compressed,
}

#[derive(Deserialize)]
struct Answer {
    token: String,
    expires_at: String,
}

/// The App JWT: `RS256`, issued a minute ago, valid for nine minutes.
fn jwt(key: &GithubAppKey, now: i64) -> Result<Zeroizing<String>, MintError> {
    let header = json!({"alg": "RS256", "typ": "JWT"});
    let claims = json!({
        "iat": now - JWT_BACKDATE_SECS,
        "exp": now + JWT_LIFETIME_SECS,
        "iss": key.app_id(),
    });
    let encode = |value: &serde_json::Value| URL_SAFE_NO_PAD.encode(value.to_string());
    let mut token = Zeroizing::new(format!("{}.{}", encode(&header), encode(&claims)));
    let signature = key
        .sign_rs256(token.as_bytes())
        .map_err(|_| MintError::Key)?;
    token.push('.');
    token.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok(token)
}

/// Mint an installation token for `key`'s installation with the fixed
/// [`PERMISSIONS`] and exactly one repository. `now` is Unix seconds.
///
/// The client trusts the system roots (or the pinned CA), refuses redirects and
/// never retries.
///
/// # Errors
/// A [`MintError`]; nothing partial is returned.
pub async fn mint(
    api: &GithubApi,
    key: &GithubAppKey,
    now: i64,
) -> Result<InstallationToken, MintError> {
    let signer = key.clone();
    // RSA signing takes milliseconds of CPU: keep it off the async workers.
    let jwt = tokio::task::spawn_blocking(move || jwt(&signer, now))
        .await
        .map_err(|_| MintError::Key)??;
    let url = api
        .base
        .join(&format!(
            "app/installations/{}/access_tokens",
            key.installation_id()
        ))
        .map_err(|_| MintError::Unreachable)?;
    let mut bearer =
        HeaderValue::from_str(&format!("Bearer {}", jwt.as_str())).map_err(|_| MintError::Key)?;
    bearer.set_sensitive(true);
    let permissions: serde_json::Map<String, serde_json::Value> = PERMISSIONS
        .iter()
        .map(|(name, level)| ((*name).to_owned(), json!(level)))
        .collect();
    let body =
        json!({ "permissions": permissions, "repository_ids": [key.repository_id()] }).to_string();
    let request = api
        .client()?
        .post(url)
        .header(AUTHORIZATION, bearer)
        .header(ACCEPT, "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header(
            USER_AGENT,
            concat!("warden-broker/", env!("CARGO_PKG_VERSION")),
        )
        .header(ACCEPT_ENCODING, "identity")
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    let mut response = request.send().await.map_err(failed)?;
    if response.status() != StatusCode::CREATED {
        // The body is never read: nothing GitHub says is passed on.
        return Err(MintError::Refused(response.status().as_u16()));
    }
    refuse_encoded(response.headers())?;
    if response
        .content_length()
        .is_some_and(|len| usize::try_from(len).map_or(true, |len| len > MAX_RESPONSE_BYTES))
    {
        return Err(MintError::TooLarge);
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(MAX_RESPONSE_BYTES));
    while let Some(chunk) = response.chunk().await.map_err(failed)? {
        if chunk.len() > MAX_RESPONSE_BYTES - raw.len() {
            return Err(MintError::TooLarge);
        }
        raw.extend_from_slice(&chunk);
    }
    parse(&raw, now)
}

/// The token and expiry in `raw`, which must expire after `now` and within
/// [`MAX_TOKEN_LIFETIME_SECS`].
fn parse(raw: &[u8], now: i64) -> Result<InstallationToken, MintError> {
    let Answer { token, expires_at } =
        serde_json::from_slice(raw).map_err(|_| MintError::Malformed)?;
    let token = SecretString::from(token);
    let expires_at = expires_at
        .parse::<jiff::Timestamp>()
        .map_err(|_| MintError::Malformed)?
        .as_second();
    if token.expose_secret().is_empty()
        || expires_at <= now
        || expires_at > now.saturating_add(MAX_TOKEN_LIFETIME_SECS)
    {
        return Err(MintError::Malformed);
    }
    Ok(InstallationToken { token, expires_at })
}

/// The fixed error for a failed send or body read. The detail goes to the log
/// without the URL.
fn failed(e: reqwest::Error) -> MintError {
    tracing::warn!(error = %e.without_url(), "the GitHub call failed");
    MintError::Unreachable
}

/// Refuse any `Content-Encoding` other than `identity`, and any
/// `Transfer-Encoding` other than `chunked`/`identity`.
fn refuse_encoded(headers: &HeaderMap) -> Result<(), MintError> {
    let only = |name: http::HeaderName, allowed: &[&str]| {
        headers.get_all(name).iter().all(|value| {
            value.to_str().is_ok_and(|text| {
                text.split(',')
                    .map(str::trim)
                    .filter(|token| !token.is_empty())
                    .all(|token| allowed.iter().any(|ok| token.eq_ignore_ascii_case(ok)))
            })
        })
    };
    if only(http::header::CONTENT_ENCODING, &["identity"])
        && only(http::header::TRANSFER_ENCODING, &["chunked", "identity"])
    {
        Ok(())
    } else {
        Err(MintError::Compressed)
    }
}

#[cfg(test)]
mod tests;

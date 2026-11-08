//! A fixed GitHub App key for tests: generated once with `openssl`, committed under
//! `github_app/` and named `throwaway-test-only`. It protects nothing.

use crate::policy::GithubAppKey;

/// The App id of [`github_app_key`].
pub const APP_ID: &str = "123456";

/// The installation id of [`github_app_key`].
pub const INSTALLATION_ID: u64 = 7_654_321;

/// A 2048-bit RSA key as PKCS#1 PEM.
pub const RSA2048_PKCS1: &[u8] = include_bytes!("github_app/throwaway-test-only-rsa2048-pkcs1.pem");
/// The same key as PKCS#8 PEM.
pub const RSA2048_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-rsa2048-pkcs8.pem");
/// The same key, encrypted with a passphrase, as PKCS#8 PEM.
pub const RSA2048_ENCRYPTED: &[u8] =
    include_bytes!("github_app/throwaway-test-only-rsa2048-encrypted-pkcs8.pem");
/// A 1024-bit RSA key, too short to accept.
pub const RSA1024_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-rsa1024-pkcs8.pem");
/// An ECDSA P-256 key.
pub const EC_P256_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-ec-p256-pkcs8.pem");
/// An Ed25519 key.
pub const ED25519_PKCS8: &[u8] = include_bytes!("github_app/throwaway-test-only-ed25519-pkcs8.pem");
/// The public half of the 2048-bit key, as a PKCS#1 `RSAPublicKey` DER, to verify
/// signatures with.
pub const RSA2048_PUBLIC_DER: &[u8] =
    include_bytes!("github_app/throwaway-test-only-rsa2048-public.der");

/// The fixed test App, and its public key for verifying what it signs.
///
/// # Panics
/// Never, unless the committed fixture is damaged.
#[must_use]
pub fn github_app_key() -> (GithubAppKey, Vec<u8>) {
    let key = GithubAppKey::new(APP_ID.to_owned(), INSTALLATION_ID, RSA2048_PKCS8)
        .expect("the committed test key loads");
    (key, RSA2048_PUBLIC_DER.to_vec())
}

//! Wire types of GitHub App tokens: the broker holds the App's private key and
//! mints short-lived installation tokens for an agent that has an active
//! `github_token` grant. The key never leaves the broker.

use std::fmt;

use serde::{Deserialize, Serialize};

/// What the broker says when the agent has no active GitHub token grant: never
/// had one, or it ended or was revoked. The CLI recognises it to say how to ask.
pub const NO_ACTIVE_GRANT: &str = "no active GitHub token grant for this agent";

/// What the broker says when the App or installation is no longer the one the
/// owner approved. The CLI recognises it to say a new grant is needed.
pub const APP_CHANGED: &str = "the GitHub App changed; request a new grant";

/// What the broker says when it holds no GitHub App.
pub const NOT_CONFIGURED: &str = "GitHub tokens are not configured on this broker";

/// The permissions every minted token has, as GitHub names them. Fixed: no
/// workflows and no administration, whatever the App itself is allowed.
pub const PERMISSIONS: [(&str, &str); 4] = [
    ("contents", "write"),
    ("pull_requests", "write"),
    ("issues", "write"),
    ("metadata", "read"),
];

/// GitHub token grant details. The private key itself is never part of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubTokenGrant {
    /// The App's id, as the owner approved it.
    pub app_id: String,
    /// The installation the tokens are minted for.
    pub installation_id: u64,
    /// Lowercase hex digest of the approved App and installation: minting is
    /// refused once the broker's App no longer matches it.
    pub digest: String,
}

/// A token the broker minted and recorded.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubTokenResponse {
    /// The installation token. A secret: `Debug` redacts it.
    pub token: String,
    /// When GitHub ends the token, in seconds since the Unix epoch.
    pub expires_at: i64,
    /// The grant it was minted under.
    pub grant_id: crate::Id,
}

impl fmt::Debug for GithubTokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubTokenResponse")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("grant_id", &self.grant_id)
            .finish()
    }
}

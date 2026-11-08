//! The GitHub token grant's own rules: its windows, the policy the App makes and
//! finding an agent's active grant.
//!
//! An agent holds at most one: approving a new grant ends the one it replaces (see
//! `renewal`), so that revoking a grant really does stop that agent's minting.

use sqlx::Row as _;
use warden_broker_proto::{AgentName, GithubTokenGrant, GrantAccess, GrantView, Id, Window};

use super::{RequestError, Requests, parse};
use crate::audit::AuditEvent;
use crate::policy::GithubTokenPolicy;

/// A usable GitHub token grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGithubToken {
    /// The grant.
    pub grant_id: Id,
    /// What was approved.
    pub grant: GithubTokenGrant,
}

/// Whether a GitHub token grant may have `window`, under the server's `max`.
pub(super) fn check_window(window: Window, max: Window) -> Result<(), String> {
    if !window.is_github_token() {
        return Err("a GitHub token grant lasts 1d, 7d or 30d".to_owned());
    }
    super::check_window(window, max, "GitHub tokens")
}

impl Requests {
    /// Allow GitHub token grants of up to `max`, instead of the default 30 days.
    #[must_use]
    pub const fn with_github_token_max(mut self, max: Window) -> Self {
        self.github_token_max = max;
        self
    }

    /// The longest GitHub token grant the server allows.
    #[must_use]
    pub const fn github_token_max(&self) -> Window {
        self.github_token_max
    }

    /// What a GitHub token grant would be bound to now: the App the broker holds.
    ///
    /// # Errors
    /// [`RequestError::Rejected`] if the broker holds no App,
    /// [`RequestError::Unavailable`] if it cannot be read.
    pub(super) async fn github_token_policy(&self) -> Result<GithubTokenPolicy, RequestError> {
        Ok(self
            .backend
            .github_app()
            .await?
            .policy(self.github_token_max))
    }

    /// The GitHub token grant `agent` may mint with now, if any. Read for every
    /// mint, so that a revocation or the end of the window stops the next one.
    ///
    /// # Errors
    /// Storage failures or an unreadable stored grant: the caller refuses.
    pub async fn active_github_token(
        &self,
        agent: &AgentName,
    ) -> Result<Option<ActiveGithubToken>, RequestError> {
        let Some(row) = self
            .active_rows(agent, "github_token")
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        let view: String = row.try_get("view")?;
        let view: GrantView = serde_json::from_str(&view)?;
        let GrantAccess::GithubToken(grant) = view.access else {
            return Err(RequestError::Corrupt(
                "GitHub token grant changed kind".to_owned(),
            ));
        };
        Ok(Some(ActiveGithubToken {
            grant_id: parse(&row, "id")?,
            grant,
        }))
    }

    /// Record that `agent` was refused a GitHub token, for `reason` (a fixed phrase).
    /// Past a few a minute only a count is kept, written later as one entry.
    pub(crate) async fn record_github_token_refusal(
        &self,
        agent: &AgentName,
        grant_id: Option<Id>,
        reason: String,
    ) {
        let event = AuditEvent::GithubTokenRefused {
            agent: agent.clone(),
            grant_id,
            reason,
        };
        self.github_refusals
            .record(
                &self.audit,
                agent,
                self.clock.now(),
                event,
                "a refusal to mint",
            )
            .await;
    }

    /// Write the refusals to mint held back since the last time.
    pub(super) async fn flush_github_refusals(&self) {
        self.github_refusals
            .flush(&self.audit, "refusals to mint", |agent, count| {
                AuditEvent::GithubTokenRefusalsHeld { agent, count }
            })
            .await;
    }
}

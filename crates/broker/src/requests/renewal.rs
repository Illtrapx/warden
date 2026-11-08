//! Grants an agent holds one of at a time: approving a new one ends the one it
//! replaces, in the same transaction, so that revoking the grant on the owner's
//! screen really does stop that agent's access.

use sqlx::{Sqlite, Transaction};
use warden_broker_proto::{AgentName, GrantAccess, Id};

use super::{RequestError, Requests, parse};
use crate::audit::AuditEvent;

/// Recorded as `by` for a grant ended by approving its replacement.
const RENEWED: &str = "renewed";

/// The stored kind of the grants `access` replaces when approved, or `None` for a
/// kind an agent may hold any number of.
pub(super) const fn replaced_kind(access: &GrantAccess) -> Option<&'static str> {
    match access {
        GrantAccess::CommitSigning(_) => Some("commit_signing"),
        GrantAccess::GithubToken(_) => Some("github_token"),
        GrantAccess::Ssh(_) | GrantAccess::Relay(_) | GrantAccess::Api(_) => None,
    }
}

/// End the other active grants of `kind` of `agent` at `now`, in `tx`, which also
/// stores `kept`, the grant replacing them. Returns their requests.
pub(super) async fn end_renewed(
    tx: &mut Transaction<'static, Sqlite>,
    agent: &AgentName,
    kept: &Id,
    kind: &str,
    now: i64,
) -> Result<Vec<Id>, RequestError> {
    let requests = sqlx::query(
        "UPDATE grants SET revoked_at = ?1 \
         WHERE agent = ?2 AND id != ?3 AND revoked_at IS NULL AND not_after > ?1 \
         AND json_extract(view, '$.access.kind') = ?4 \
         RETURNING request_id",
    )
    .bind(now)
    .bind(agent.as_str())
    .bind(kept.as_str())
    .bind(kind)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| parse(row, "request_id"))
    .collect::<Result<Vec<Id>, _>>()?;
    for request in &requests {
        sqlx::query("UPDATE requests SET status = 'revoked' WHERE id = ? AND status = 'approved'")
            .bind(request.as_str())
            .execute(&mut **tx)
            .await?;
    }
    Ok(requests)
}

impl Requests {
    /// The entries for ending the active grants of `kind` that a new grant of
    /// `agent` replaces. Written with the approval, before anything changes.
    pub(super) async fn renewal_events(
        &self,
        agent: &AgentName,
        kind: &str,
    ) -> Result<Vec<AuditEvent>, RequestError> {
        sqlx::query(
            "SELECT id FROM grants \
             WHERE agent = ?1 AND revoked_at IS NULL AND not_after > ?2 \
             AND json_extract(view, '$.access.kind') = ?3 \
             ORDER BY not_after DESC, id",
        )
        .bind(agent.as_str())
        .bind(self.clock.now())
        .bind(kind)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| {
            Ok(AuditEvent::GrantRevoked {
                grant_id: parse(row, "id")?,
                by: RENEWED.to_owned(),
            })
        })
        .collect()
    }
}

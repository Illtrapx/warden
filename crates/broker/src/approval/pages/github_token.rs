//! What the pages say about GitHub tokens. Its wording matters: the owner must see
//! how far one grant reaches, which is every repository the App is installed on,
//! and that a minted token outlives the grant's revocation.

use maud::{Markup, html};
use warden_broker_proto::github_token::PERMISSIONS;

use super::{icon, warning_icon};

/// The warning of what the access can change.
fn reach() -> Markup {
    html! {
        strong.badge.modify {
            (icon(14, "2.4", &warning_icon()))
            " Can push and merge on every repository the App is installed on"
        }
    }
}

/// The permissions every token has.
fn permissions() -> Markup {
    html! {
        span.detail {
            "Permissions: "
            @for (i, (name, level)) in PERMISSIONS.into_iter().enumerate() {
                @if i > 0 { ", " }
                code { (name) ": " (level) }
            }
        }
    }
}

/// What a revocation does and does not stop.
const REVOKING: &str = "Revoking the grant stops new tokens at once, but tokens last 1 hour and \
                        cannot be recalled when revoked.";

/// The App and installation, as the owner approves and later reads them.
fn app(app_id: &str, installation_id: u64) -> Markup {
    html! { "GitHub App " code { bdi { (app_id) } } ", installation " code { (installation_id) } }
}

/// What approving GitHub tokens gives, for the approval and pending pages.
pub(super) fn access(app_id: &str, installation_id: u64) -> Markup {
    html! {
        span { "Mint tokens for " (app(app_id, installation_id)) }
        (reach())
        (permissions())
        span.detail {
            "warden mints a token whenever this agent asks, until the grant ends or is revoked, \
             and records each one. " (REVOKING)
        }
    }
}

/// What an active GitHub token grant gives, for the grants page.
pub(super) fn grant_access(app_id: &str, installation_id: u64) -> Markup {
    html! {
        span { "Mints tokens for " (app(app_id, installation_id)) }
        (reach())
        (permissions())
        span.detail { (REVOKING) }
    }
}

/// The grants page's note where other grants show what they are doing.
pub(super) fn live_note() -> Markup {
    html! {
        p.detail {
            "Tokens are minted when the agent asks, each lasting 1 hour, and every mint is in \
             the audit log."
        }
    }
}

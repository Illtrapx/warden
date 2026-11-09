//! The doctor check of GitHub tokens: if git takes its GitHub credential from
//! warden, that it takes it from warden alone, and whether this agent has a grant.

use std::process::Command;

use warden_broker_proto::doctor::Check;
use warden_broker_proto::{GrantAccess, GrantView};

use super::FIX_EARLIER;
use crate::client::CallError;

/// The check's name.
pub const NAME: &str = "github.token";

/// The git setting `warden setup github` makes.
const HELPER_KEY: &str = "credential.https://github.com.helper";

/// The values of [`HELPER_KEY`] as git reads them, in order, every scope included.
pub fn live_helpers() -> Vec<String> {
    Command::new("git")
        .args(["config", "--get-all", HELPER_KEY])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether `grants` hold a GitHub token grant.
pub fn has_grant(grants: &[GrantView]) -> bool {
    grants
        .iter()
        .any(|grant| matches!(grant.access, GrantAccess::GithubToken(_)))
}

/// Whether `helper` is this program's credential helper, as `warden setup github`
/// writes it.
fn is_warden(helper: &str) -> bool {
    helper.starts_with('!') && helper.ends_with(" git-credential") && helper.contains("warden")
}

/// Whether git takes its GitHub credential from warden, among others or not.
pub fn through_warden(helpers: &[String]) -> bool {
    helpers.iter().any(|helper| is_warden(helper))
}

/// The check: `helpers` are git's values of [`HELPER_KEY`]; `grant` is whether this
/// agent has an active grant, `None` when the broker was not asked.
pub fn check(helpers: &[String], grant: Option<Result<bool, CallError>>) -> Check {
    const SETUP: &str = "Run `warden setup github`.";
    if !through_warden(helpers) {
        return Check::pass(
            NAME,
            "Git does not take GitHub credentials from warden here; `warden setup github` would \
             set that up.",
        );
    }
    // An empty value drops the helpers before it, so what counts follows the last.
    let used = helpers
        .iter()
        .rposition(String::is_empty)
        .map_or(helpers, |last| &helpers[last + 1..]);
    if !matches!(used, [only] if is_warden(only)) {
        return Check::fail(
            NAME,
            "Git consults other credential helpers for https://github.com as well as warden's.",
            SETUP,
        );
    }
    match grant {
        None => Check::could_not_check(
            NAME,
            "Not checked: the credential is not available.",
            FIX_EARLIER,
        ),
        Some(Err(CallError::Unavailable(reason) | CallError::CallStopped(reason))) => {
            Check::could_not_check(
                NAME,
                reason,
                "Get the broker answering, then run doctor again. git and gh get no GitHub \
                 token until it does.",
            )
        }
        Some(Err(e)) => Check::fail(
            NAME,
            e.to_string(),
            "Ask the owner whether GitHub tokens are configured on the broker.",
        ),
        Some(Ok(true)) => Check::pass(
            NAME,
            "Git takes GitHub tokens from warden, and this agent has an active grant.",
        ),
        Some(Ok(false)) => Check::pass(
            NAME,
            "Git takes GitHub tokens from warden. This agent has no active grant yet: the first \
             git or gh call to GitHub asks the owner for one and waits.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use warden_broker_proto::doctor::Status;

    use super::check;
    use crate::client::CallError;

    const OURS: &str = "!'/opt/bin/warden' git-credential";

    fn helpers(list: &[&str]) -> Vec<String> {
        list.iter().map(|h| (*h).to_owned()).collect()
    }

    #[test]
    fn git_that_does_not_use_warden_for_github_is_fine() {
        for list in [&[][..], &["osxkeychain"][..]] {
            let result = check(&helpers(list), None);
            assert_eq!(result.status, Status::Pass, "{list:?}");
        }
    }

    #[test]
    fn warden_alone_with_or_without_a_grant_passes() {
        for list in [&["", OURS][..], &["osxkeychain", "", OURS][..], &[OURS][..]] {
            let with = check(&helpers(list), Some(Ok(true)));
            assert_eq!(with.status, Status::Pass, "{list:?}");
            assert!(with.detail.contains("active grant"), "{}", with.detail);
        }
        let without = check(&helpers(&["", OURS]), Some(Ok(false)));
        assert_eq!(without.status, Status::Pass);
        assert!(
            without.detail.contains("asks the owner"),
            "{}",
            without.detail
        );
    }

    #[test]
    fn other_helpers_alongside_warden_fail() {
        for list in [&["", OURS, "osxkeychain"][..], &["osxkeychain", OURS][..]] {
            let result = check(&helpers(list), Some(Ok(true)));
            assert_eq!(result.status, Status::Fail, "{list:?}");
        }
    }

    #[test]
    fn the_broker_not_answering_is_not_a_verdict() {
        let out = Some(Err(CallError::Unavailable("down".to_owned())));
        assert_eq!(
            check(&helpers(&["", OURS]), out).status,
            Status::CouldNotCheck
        );
        assert_eq!(
            check(&helpers(&["", OURS]), None).status,
            Status::CouldNotCheck
        );
        let refused = Some(Err(CallError::Refused("no".to_owned())));
        assert_eq!(check(&helpers(&["", OURS]), refused).status, Status::Fail);
    }
}

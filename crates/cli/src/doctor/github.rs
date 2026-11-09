//! The doctor check of GitHub tokens: if git takes its GitHub credential from
//! warden, that it takes it from this warden alone, and whether this agent has a
//! grant.
//!
//! Git asks one list of helpers for `https://github.com`: the generic
//! `credential.helper` values and those of every `credential.<url>.helper` whose
//! URL matches, in the order git reads its configuration, an empty value dropping
//! all before it (gitcredentials(7)). Which URLs match is left to git itself.

use std::io::Write as _;
use std::process::{Command, Stdio};

use warden_broker_proto::doctor::Check;
use warden_broker_proto::{GrantAccess, GrantView};

use super::FIX_EARLIER;
use crate::client::CallError;
use crate::setup_github::helper_program;

/// The check's name.
pub const NAME: &str = "github.token";

/// The URL git asks about.
const GITHUB: &str = "https://github.com";

/// How git is set up to get GitHub credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GithubSetup {
    /// The helpers git asks for GitHub, in order, empty values included.
    pub helpers: Vec<String>,
    /// The helper `warden setup github` would write for this program, if it can
    /// tell where it is.
    pub this_helper: Option<String>,
}

/// Every `credential.*helper` entry of git's configuration as `(key, value)`, in
/// the order git reads them. `configure` sets the command up (tests point it at
/// their own configuration).
fn helper_entries(configure: impl Fn(&mut Command)) -> Vec<(String, String)> {
    let mut cmd = Command::new("git");
    configure(&mut cmd);
    let Some(out) = cmd
        .args([
            "config",
            "--null",
            "--get-regexp",
            r"^credential\.(.*\.)?helper$",
        ])
        .output()
        .ok()
        .filter(|out| out.status.success())
    else {
        return Vec::new();
    };
    out.stdout
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            match entry.split_once('\n') {
                Some((key, value)) => (key.to_owned(), value.to_owned()),
                None => (entry.into_owned(), String::new()),
            }
        })
        .collect()
}

/// Whether git applies `credential.<pattern>.*` to [`GITHUB`], as git's own URL
/// matching says. A pattern without a scheme is a partial URL, which matches any
/// scheme, so it is asked about as an https one.
fn pattern_matches(pattern: &str, configure: &impl Fn(&mut Command)) -> bool {
    let url = if pattern.contains("://") {
        pattern.to_owned()
    } else {
        format!("https://{pattern}")
    };
    let subsection = url.replace('\\', r"\\").replace('"', "\\\"");
    let mut cmd = Command::new("git");
    configure(&mut cmd);
    let Ok(mut child) = cmd
        .args([
            "config",
            "--file",
            "-",
            "--get-urlmatch",
            "credential.helper",
            GITHUB,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let wrote = child.stdin.take().is_some_and(|mut stdin| {
        stdin
            .write_all(format!("[credential \"{subsection}\"]\n\thelper = x\n").as_bytes())
            .is_ok()
    });
    child
        .wait_with_output()
        .is_ok_and(|out| wrote && out.status.success() && out.stdout == b"x\n")
}

/// The values of `entries` that git asks for GitHub, in order: the generic ones and
/// those whose URL `matches`.
fn github_helpers(entries: &[(String, String)], matches: impl Fn(&str) -> bool) -> Vec<String> {
    entries
        .iter()
        .filter(|(key, _)| {
            key == "credential.helper"
                || key
                    .strip_prefix("credential.")
                    .and_then(|rest| rest.strip_suffix(".helper"))
                    .is_some_and(&matches)
        })
        .map(|(_, value)| value.clone())
        .collect()
}

/// How git is set up here, as `configure` points it.
fn setup_with(configure: impl Fn(&mut Command)) -> GithubSetup {
    let entries = helper_entries(&configure);
    GithubSetup {
        helpers: github_helpers(&entries, |pattern| pattern_matches(pattern, &configure)),
        this_helper: crate::setup_github::this_helper(),
    }
}

/// How git is set up here.
pub fn live_setup() -> GithubSetup {
    setup_with(|_| {})
}

/// Whether `grants` hold a GitHub token grant.
pub fn has_grant(grants: &[GrantView]) -> bool {
    grants
        .iter()
        .any(|grant| matches!(grant.access, GrantAccess::GithubToken(_)))
}

/// Whether `helper` runs a warden: this one's exact value, or the shape `warden
/// setup github` writes naming a program called `warden`.
fn is_warden(helper: &str, this_helper: Option<&str>) -> bool {
    Some(helper) == this_helper
        || helper_program(helper).is_some_and(|program| {
            std::path::Path::new(&program)
                .file_name()
                .is_some_and(|name| name == "warden")
        })
}

/// Whether git takes its GitHub credential from a warden, among others or not.
pub fn through_warden(setup: &GithubSetup) -> bool {
    setup
        .helpers
        .iter()
        .any(|helper| is_warden(helper, setup.this_helper.as_deref()))
}

/// The check: `setup` is how git asks for GitHub credentials; `grant` is whether
/// this agent has an active grant, `None` when the broker was not asked.
pub fn check(setup: &GithubSetup, grant: Option<Result<bool, CallError>>) -> Check {
    const SETUP: &str = "Run `warden setup github`.";
    if !through_warden(setup) {
        return Check::pass(
            NAME,
            "Git does not take GitHub credentials from warden here; `warden setup github` would \
             set that up.",
        );
    }
    // An empty value drops the helpers before it, so what counts follows the last.
    let helpers = &setup.helpers;
    let used = helpers
        .iter()
        .rposition(String::is_empty)
        .map_or(&helpers[..], |last| &helpers[last + 1..]);
    let [only] = used else {
        return Check::fail(
            NAME,
            "Git asks other credential helpers for https://github.com as well as warden's, or \
             none.",
            SETUP,
        );
    };
    if setup.this_helper.as_ref() != Some(only) {
        return Check::fail(
            NAME,
            "Git's credential helper for https://github.com is not this warden.",
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
mod tests;

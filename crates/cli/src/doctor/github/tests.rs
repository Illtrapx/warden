use std::fs;
use std::path::Path;
use std::process::Command;

use warden_broker_proto::doctor::Status;

use super::{GithubSetup, check, github_helpers, setup_with};
use crate::client::CallError;

const OURS: &str = "!'/opt/bin/warden' git-credential";

fn setup(list: &[&str]) -> GithubSetup {
    GithubSetup {
        helpers: list.iter().map(|h| (*h).to_owned()).collect(),
        this_helper: Some(OURS.to_owned()),
    }
}

#[test]
fn git_that_does_not_use_warden_for_github_is_fine() {
    for list in [&[][..], &["osxkeychain"][..], &["!/opt/warden-tools/x"][..]] {
        let result = check(&setup(list), None);
        assert_eq!(result.status, Status::Pass, "{list:?}");
    }
}

#[test]
fn warden_alone_with_or_without_a_grant_passes() {
    for list in [&["", OURS][..], &["osxkeychain", "", OURS][..], &[OURS][..]] {
        let with = check(&setup(list), Some(Ok(true)));
        assert_eq!(with.status, Status::Pass, "{list:?}");
        assert!(with.detail.contains("active grant"), "{}", with.detail);
    }
    let without = check(&setup(&["", OURS]), Some(Ok(false)));
    assert_eq!(without.status, Status::Pass);
    assert!(
        without.detail.contains("asks the owner"),
        "{}",
        without.detail
    );
}

#[test]
fn a_helper_before_or_after_wardens_fails() {
    for list in [
        &["osxkeychain", OURS][..],
        &["", OURS, "osxkeychain"][..],
        &["osxkeychain", "", OURS, "store"][..],
        &["", OURS, ""][..],
    ] {
        let result = check(&setup(list), Some(Ok(true)));
        assert_eq!(result.status, Status::Fail, "{list:?}");
    }
}

#[test]
fn another_warden_than_this_one_fails() {
    let elsewhere = "!'/old/place/warden' git-credential";
    let result = check(&setup(&["", elsewhere]), Some(Ok(true)));
    assert_eq!(result.status, Status::Fail);
    assert!(
        result.detail.contains("not this warden"),
        "{}",
        result.detail
    );
}

#[test]
fn the_broker_not_answering_is_not_a_verdict() {
    let out = Some(Err(CallError::Unavailable("down".to_owned())));
    assert_eq!(
        check(&setup(&["", OURS]), out).status,
        Status::CouldNotCheck
    );
    assert_eq!(
        check(&setup(&["", OURS]), None).status,
        Status::CouldNotCheck
    );
    let refused = Some(Err(CallError::Refused("no".to_owned())));
    assert_eq!(check(&setup(&["", OURS]), refused).status, Status::Fail);
}

#[test]
fn generic_and_matching_helpers_are_taken_together_in_order() {
    let entries: Vec<(String, String)> = [
        ("credential.helper", "first"),
        ("credential.https://github.com.helper", ""),
        ("credential.https://github.com.helper", "ours"),
        ("credential.https://gitlab.com.helper", "gitlab"),
        ("credential.helper", "last"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    let helpers = github_helpers(&entries, |pattern| pattern == "https://github.com");
    assert_eq!(helpers, ["first", "", "ours", "last"]);
}

/// Git's own reading of a configuration file, with no system or repository
/// configuration.
fn helpers_of(config: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("gitconfig");
    fs::write(&file, config).unwrap();
    let configure = |cmd: &mut Command| {
        cmd.env("GIT_CONFIG_GLOBAL", &file)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_DIR")
            .current_dir(Path::new(dir.path()));
    };
    setup_with(configure).helpers
}

#[test]
fn git_decides_which_urls_match() {
    let helpers = helpers_of(
        "[credential]\n\thelper = first\n\
         [credential \"https://github.com\"]\n\thelper =\n\thelper = ours\n\
         [credential \"https://gitlab.com\"]\n\thelper = gitlab\n\
         [credential \"https://github.com/some/repo\"]\n\thelper = pathy\n\
         [credential \"github.com\"]\n\thelper = hostonly\n\
         [credential \"https://*.github.com\"]\n\thelper = sub\n\
         [credential \"http://github.com\"]\n\thelper = plain\n\
         [credential]\n\thelper = last\n",
    );
    // What `git credential fill` consults, in this order, as git 2.54 does.
    assert_eq!(helpers, ["first", "", "ours", "hostonly", "last"]);
}

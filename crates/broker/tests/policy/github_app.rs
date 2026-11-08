//! The GitHub App item.

use serde_json::{Value, json};
use warden_broker::policy::{PolicyError, SecretBackend};
use warden_broker::testkit::github_app::{APP_ID, INSTALLATION_ID, RSA2048_PKCS1, RSA2048_PKCS8};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::{TOKEN, VAULT_ID, backend, connect_mock, mount_item, mount_items};

fn summaries(ids: &[&str]) -> Value {
    Value::Array(
        ids.iter()
            .map(|id| {
                json!({
                    "id": id, "title": format!("github-app-{id}"), "category": "API_CREDENTIAL",
                    "vault": {"id": VAULT_ID}, "tags": ["warden:github-app"]
                })
            })
            .collect(),
    )
}

fn field(id: &str, value: &str) -> Value {
    json!({"id": id, "type": "CONCEALED", "label": id, "value": value})
}

fn item(id: &str, fields: &[Value]) -> Value {
    json!({
        "id": id, "title": format!("github-app-{id}"), "vault": {"id": VAULT_ID},
        "tags": ["warden:github-app"], "fields": fields
    })
}

fn full(pem: &[u8]) -> Vec<Value> {
    vec![
        field("app_id", APP_ID),
        field("installation_id", &INSTALLATION_ID.to_string()),
        field("private_key", std::str::from_utf8(pem).unwrap()),
    ]
}

async fn with_item(fields: Vec<Value>) -> MockServer {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&["ga1"])).await;
    mount_item(&server, "ga1", &item("ga1", &fields)).await;
    server
}

fn reason(err: &PolicyError) -> &str {
    match err {
        PolicyError::GithubApp(reason) => reason,
        other => panic!("not a GitHub App error: {other:?}"),
    }
}

#[tokio::test]
async fn github_app_loads_from_the_tagged_item() {
    let server = with_item(full(RSA2048_PKCS1)).await;
    let key = backend(&server).github_app().await.unwrap();
    assert!(format!("{key:?}").contains(APP_ID));
    assert!(backend(&server).has_github_app().await.unwrap());
}

#[tokio::test]
async fn github_app_absent_is_not_configured() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&[])).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(matches!(err, PolicyError::NoGithubApp), "{err:?}");
    assert!(!backend(&server).has_github_app().await.unwrap());
}

#[tokio::test]
async fn two_github_app_items_is_an_error() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&["ga1", "ga2"])).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(reason(&err).contains("exactly one"), "{err:?}");
    assert!(backend(&server).has_github_app().await.unwrap());
}

#[tokio::test]
async fn github_app_missing_field_is_invalid() {
    for missing in ["app_id", "installation_id", "private_key"] {
        let mut fields = full(RSA2048_PKCS8);
        fields.retain(|f| f["id"] != missing);
        let server = with_item(fields).await;
        let err = backend(&server).github_app().await.unwrap_err();
        assert!(reason(&err).contains(missing), "{missing}: {err:?}");

        let mut blank = full(RSA2048_PKCS8);
        for f in &mut blank {
            if f["id"] == missing {
                f["value"] = json!("  ");
            }
        }
        let server = with_item(blank).await;
        let err = backend(&server).github_app().await.unwrap_err();
        assert!(reason(&err).contains(missing), "{missing}: {err:?}");
    }
}

#[tokio::test]
async fn github_app_non_numeric_installation_is_invalid() {
    for bad in ["abc", "-1", "0", "1.5", "99999999999999999999999"] {
        let mut fields = full(RSA2048_PKCS8);
        fields[1] = field("installation_id", bad);
        let server = with_item(fields).await;
        let err = backend(&server).github_app().await.unwrap_err();
        assert!(reason(&err).contains("installation_id"), "{bad}: {err:?}");
        assert!(!err.to_string().contains(bad), "echoed {bad}: {err}");
    }
}

#[tokio::test]
async fn github_app_bad_key_is_invalid_and_never_quoted() {
    let mut fields = full(RSA2048_PKCS8);
    fields[2] = field("private_key", "SECRET-NOT-A-KEY");
    let server = with_item(fields).await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(reason(&err).contains("private_key"), "{err:?}");
    assert!(!err.to_string().contains("SECRET-NOT-A-KEY"), "{err}");
    assert!(!err.to_string().contains(TOKEN), "{err}");
}

#[tokio::test]
async fn github_app_read_once_per_call() {
    let server = with_item(full(RSA2048_PKCS8)).await;
    let connect = backend(&server);
    connect.github_app().await.unwrap();
    connect.github_app().await.unwrap();
    let item_path = format!("/v1/vaults/{VAULT_ID}/items/ga1");
    let reads = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == item_path)
        .count();
    assert_eq!(reads, 2);
    // Asking only whether there is one reads no item at all.
    connect.has_github_app().await.unwrap();
    let reads_after = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == item_path)
        .count();
    assert_eq!(reads_after, 2);
}

#[tokio::test]
async fn github_app_unreadable_item_never_quotes_it() {
    let server = connect_mock().await;
    mount_items(&server, &summaries(&["ga1"])).await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/vaults/{VAULT_ID}/items/ga1")))
        .respond_with(ResponseTemplate::new(200).set_body_string("{\"fields\": SECRET"))
        .mount(&server)
        .await;
    let err = backend(&server).github_app().await.unwrap_err();
    assert!(!err.to_string().contains("SECRET"), "{err}");
}

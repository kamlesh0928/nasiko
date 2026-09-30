//! Integration tests for `POST /api/import/upload` (`oss/server/src/catalog/import.rs`).
//!
//! Scoped to Task 1.6 (spec §16 A4): `build_and_deploy` — shared by `import_upload`,
//! `import_github`, and `import_registry`'s source-artifact branch — must reject before its own
//! `(owner_id, name)` upsert when an existing row by that key is a CLI-bound coding agent. Only
//! `import_upload` has a real test harness (no OAuth/registry mocking needed — see the module doc
//! in `coding_agent.rs` for the other two, untested at the integration level for that reason).
//!
//! Requires infra (Postgres :5432, Redis, S3):
//!   cargo test -p nasiko-server --test catalog_import -- --test-threads=1

mod common;

use serde_json::{Value, json};
use serial_test::serial;
use uuid::Uuid;

async fn init_admin(server: &common::TestServer) -> Value {
    server
        .client
        .post(server.url("/api/auth/initialize-admin"))
        .json(&json!({"username": "admin", "email": "admin@test.local"}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap()
}

/// `import_upload` calls `build_and_deploy` synchronously (no build-worker queue, unlike
/// `POST /api/agents/upload`) — a Dockerfile alongside `AgentCard.json` is enough for
/// `FakeRuntime` to carry a successful import all the way through to a real deploy.
fn make_import_zip(agent_name: &str, version: &str) -> Vec<u8> {
    let card = serde_json::json!({"name": agent_name, "version": version}).to_string();
    common::make_zip(&[
        ("AgentCard.json", card.as_bytes()),
        (
            "Dockerfile",
            b"FROM python:3.11-slim\nCMD [\"python\", \"main.py\"]",
        ),
    ])
}

async fn import_upload(server: &common::TestServer, uid: &str, zip: Vec<u8>) -> reqwest::Response {
    let form = reqwest::multipart::Form::new().part(
        "package",
        reqwest::multipart::Part::bytes(zip).file_name("agent.zip"),
    );
    common::as_superuser(
        server.client.post(server.url("/api/import/upload")),
        uid,
        "admin",
    )
    .multipart(form)
    .send()
    .await
    .unwrap()
}

#[derive(Debug, PartialEq, sqlx::FromRow)]
struct AgentSnapshot {
    coding_agent_integration_id: Option<String>,
    version: String,
    image: Option<String>,
    status: String,
}

async fn snapshot_agent(server: &common::TestServer, agent_id: Uuid) -> AgentSnapshot {
    sqlx::query_as(
        "SELECT coding_agent_integration_id, version, image, status FROM agents WHERE id = $1",
    )
    .bind(agent_id)
    .fetch_one(&server.db)
    .await
    .unwrap()
}

async fn agent_builds_count(server: &common::TestServer, agent_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agent_builds WHERE agent_id = $1")
        .bind(agent_id)
        .fetch_one(&server.db)
        .await
        .unwrap()
}

/// Task 1.6 (spec §16 A4): `build_and_deploy`'s `(owner_id, name)` guard must fire before
/// `find_owned_agent` even looks the row up — checked here via the actual HTTP route rather than
/// just the shared helper, since this is a distinct call site from `agents::upload`'s.
#[tokio::test]
#[serial]
async fn import_upload_rejects_when_name_collides_with_a_coding_agent_row_owned_by_the_caller() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    // Seed the coding-agent row directly (mirrors catalog_acl.rs's own fixtures) — its exact
    // provenance (CLI registration vs. a prior import) doesn't matter to this guard.
    let agent_id: Uuid = sqlx::query_scalar(
        "INSERT INTO agents (name, owner_id, version, image, status, coding_agent_integration_id) \
         VALUES ($1, $2, '1.0.0', 'nasiko/import-coding-agent:1.0.0', 'running', 'claude') \
         RETURNING id",
    )
    .bind("import-coding-agent")
    .bind(uuid::Uuid::parse_str(uid).unwrap())
    .fetch_one(&server.db)
    .await
    .unwrap();

    let before = snapshot_agent(&server, agent_id).await;
    let builds_before = agent_builds_count(&server, agent_id).await;

    let zip = make_import_zip("import-coding-agent", "2.0.0");
    let res = import_upload(&server, uid, zip).await;
    assert_eq!(res.status(), 409);
    let text = res.text().await.unwrap();
    assert!(
        text.contains("coding_agent_not_deployable"),
        "expected coding_agent_not_deployable, got: {text}"
    );

    let after = snapshot_agent(&server, agent_id).await;
    assert_eq!(
        after, before,
        "the row must be untouched — no upsert reached"
    );
    assert_eq!(
        agent_builds_count(&server, agent_id).await,
        builds_before,
        "no new agent_builds row must be created for a rejected import"
    );

    // Control: an ordinary (non-colliding) import in the same test still gets through as today.
    let zip = make_import_zip("import-normal-agent", "1.0.0");
    let normal = import_upload(&server, uid, zip).await;
    assert_eq!(normal.status(), 201, "a normal import must be unaffected");

    server.cleanup().await;
}

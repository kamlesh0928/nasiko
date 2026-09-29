//! Integration tests for `POST /api/agents/{id}/grants/*` (`oss/server/src/agents/grants.rs`).
//!
//! Coverage here is scoped to Task 1.6 (spec §16 A4): a coding-agent row
//! (`agents.coding_agent_integration_id IS NOT NULL`) must never be shared via `agent_grants` —
//! Task 1.5's MCP-gateway owner-fallback policy is safe only while such a row stays single-owner.
//! No other route on this router has dedicated coverage yet, so each test also proves an ordinary
//! row is unaffected by the new guard rather than assuming it from other suites.
//!
//! Requires infra (Postgres :5432, Redis, S3) like the rest of the suite:
//!   `cargo test -p nasiko-server --test agent_grants -- --test-threads=1`

mod common;

use serde_json::{Value, json};
use serial_test::serial;

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

async fn create_user(server: &common::TestServer, admin_id: &str, username: &str) -> Value {
    common::as_superuser(
        server.client.post(server.url("/api/users")),
        admin_id,
        "admin",
    )
    .json(&json!({"username": username, "email": format!("{username}@test.local")}))
    .send()
    .await
    .unwrap()
    .json::<Value>()
    .await
    .unwrap()
}

async fn create_agent(server: &common::TestServer, uid: &str, name: &str) -> Value {
    let res = common::as_superuser(server.client.post(server.url("/api/agents")), uid, "admin")
        .json(&json!({"name": name, "version": "1.0.0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "create agent should succeed");
    res.json::<Value>().await.unwrap()
}

/// Turns an already-created ordinary agent into a CLI-bound coding-agent row, the same fact
/// `oss/migrations/0019_coding_agent_identity.sql` models — direct SQL, mirroring how
/// `catalog_acl.rs`'s `is_internal`/`is_public` fixtures are set up, rather than depending on the
/// exact name/owner the real `POST /api/agents/coding-integrations` registration flow derives.
async fn mark_coding_agent(server: &common::TestServer, agent_id: &str) {
    sqlx::query("UPDATE agents SET coding_agent_integration_id = 'claude' WHERE id = $1")
        .bind(uuid::Uuid::parse_str(agent_id).unwrap())
        .execute(&server.db)
        .await
        .expect("mark coding agent");
}

async fn agent_grants_count(server: &common::TestServer, agent_id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM agent_grants WHERE agent_id = $1")
        .bind(uuid::Uuid::parse_str(agent_id).unwrap())
        .fetch_one(&server.db)
        .await
        .expect("count agent_grants")
}

async fn is_public(server: &common::TestServer, agent_id: &str) -> bool {
    sqlx::query_scalar("SELECT is_public FROM agents WHERE id = $1")
        .bind(uuid::Uuid::parse_str(agent_id).unwrap())
        .fetch_one(&server.db)
        .await
        .expect("read is_public")
}

#[tokio::test]
#[serial]
async fn add_user_grant_rejects_coding_agent_row_but_not_a_normal_one() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let grantee = create_user(&server, uid, "grants-user-grantee").await;
    let grantee_id = grantee["id"].as_str().unwrap();

    let coding_agent = create_agent(&server, uid, "grants-user-coding").await;
    let coding_id = coding_agent["id"].as_str().unwrap();
    mark_coding_agent(&server, coding_id).await;

    let rejected = common::as_superuser(
        server
            .client
            .post(server.url(&format!("/api/agents/{coding_id}/grants/users"))),
        uid,
        "admin",
    )
    .json(&json!({"user_id": grantee_id}))
    .send()
    .await
    .unwrap();
    assert_eq!(rejected.status(), 409);
    let body = rejected.text().await.unwrap();
    assert!(
        body.contains("coding_agent_unshareable"),
        "body should name the rejection reason: {body}"
    );
    assert_eq!(
        agent_grants_count(&server, coding_id).await,
        0,
        "no agent_grants row must be inserted for a rejected coding-agent share"
    );

    // Control: an ordinary row in the same test still gets through as today.
    let normal_agent = create_agent(&server, uid, "grants-user-normal").await;
    let normal_id = normal_agent["id"].as_str().unwrap();
    let accepted = common::as_superuser(
        server
            .client
            .post(server.url(&format!("/api/agents/{normal_id}/grants/users"))),
        uid,
        "admin",
    )
    .json(&json!({"user_id": grantee_id}))
    .send()
    .await
    .unwrap();
    assert_eq!(accepted.status(), 201, "a normal row must be unaffected");
    assert_eq!(agent_grants_count(&server, normal_id).await, 1);

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn make_public_rejects_coding_agent_row_but_not_a_normal_one() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let coding_agent = create_agent(&server, uid, "grants-public-coding").await;
    let coding_id = coding_agent["id"].as_str().unwrap();
    mark_coding_agent(&server, coding_id).await;

    let rejected = common::as_superuser(
        server
            .client
            .post(server.url(&format!("/api/agents/{coding_id}/grants/public"))),
        uid,
        "admin",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(rejected.status(), 409);
    let body = rejected.text().await.unwrap();
    assert!(
        body.contains("coding_agent_unshareable"),
        "body should name the rejection reason: {body}"
    );
    assert!(
        !is_public(&server, coding_id).await,
        "is_public must stay false for a rejected coding-agent share"
    );
    assert_eq!(agent_grants_count(&server, coding_id).await, 0);

    // Control: an ordinary row in the same test still gets through as today.
    let normal_agent = create_agent(&server, uid, "grants-public-normal").await;
    let normal_id = normal_agent["id"].as_str().unwrap();
    let accepted = common::as_superuser(
        server
            .client
            .post(server.url(&format!("/api/agents/{normal_id}/grants/public"))),
        uid,
        "admin",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(accepted.status(), 204, "a normal row must be unaffected");
    assert!(is_public(&server, normal_id).await);

    server.cleanup().await;
}

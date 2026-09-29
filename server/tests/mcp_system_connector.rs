//! `provider_type='system'` connector rows — schema-only coverage for
//! `0041_workspace.sql`.
//!
//! `chk_connectors_provider_fields` (0003_mcp.sql) originally allowed only the
//! `composio`/`mcp_server` field combinations; a `provider_type='system'` row
//! (however `source_kind`/`auth_type` were set) was rejected by that CHECK
//! even after `mcp_connectors_provider_type_check` was widened to permit the
//! value. This proves the migration's follow-up fix — dropping and
//! re-adding `chk_connectors_provider_fields` with a `system` clause — lets a
//! minimal system-connector row actually insert. No route or application
//! code is exercised here; a later task adds the row a real deployment would
//! use (public grant, real loopback URL) and the routes that serve it.

mod common;

use common::TestServer;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn a_minimal_system_connector_row_can_be_inserted() {
    let server = TestServer::start().await;

    // Confirms the server actually came up (migrations included) before the
    // direct-SQL assertion below — this test's whole point is the migration.
    let health = server
        .client
        .get(server.url("/health"))
        .send()
        .await
        .expect("health check must be reachable");
    assert!(health.status().is_success());

    let id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type) \
         VALUES ('system', 'system', 'workspace-test-connector', 'http://127.0.0.1:1/mcp', 'none') \
         RETURNING id",
    )
    .fetch_one(&server.db)
    .await
    .expect("a minimal provider_type='system' row must satisfy every CHECK on mcp_connectors");

    let (provider_type, source_kind): (String, String) =
        sqlx::query_as("SELECT provider_type, source_kind::text FROM mcp_connectors WHERE id = $1")
            .bind(id)
            .fetch_one(&server.db)
            .await
            .expect("row must be readable back");
    assert_eq!(provider_type, "system");
    assert_eq!(source_kind, "system");

    server.cleanup().await;
}

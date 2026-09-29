//! `provider_type='system'` connector rows — schema-only coverage for
//! `0041_workspace.sql`, plus an end-to-end proof that a system connector
//! actually works through the real gateway.
//!
//! `chk_connectors_provider_fields` (0003_mcp.sql) originally allowed only the
//! `composio`/`mcp_server` field combinations; a `provider_type='system'` row
//! (however `source_kind`/`auth_type` were set) was rejected by that CHECK
//! even after `mcp_connectors_provider_type_check` was widened to permit the
//! value. The three tests below prove the migration's follow-up fix —
//! dropping and re-adding `chk_connectors_provider_fields` with a `system`
//! clause — lets a minimal system-connector row actually insert, and that a
//! NULL `url` / non-`none` `auth_type` are still rejected by the same clause.
//!
//! `system_connector_end_to_end_through_the_real_gateway` below is the actual
//! acceptance test for Task 1.3/1.9: it inserts the rows a real deployment
//! would use (public grant, synced tool catalog, per-agent access) against a
//! real stub MCP backend and drives `/api/mcp` exactly as a deployed agent
//! would — no route or application code is exercised in the three
//! schema-only tests above.

mod common;

use std::sync::{Arc, Mutex};

use axum::{Json, Router, extract::State, http::HeaderMap, routing::post};
use common::TestServer;
use serde_json::{Value, json};
use serial_test::serial;
use uuid::Uuid;

/// SAFETY: every test in this file is `#[serial]`, so no other test observes
/// the env var mid-mutation. Same convention as `mcp_e2e_agent_flow.rs`,
/// `mcp_connectors.rs`, `mcp_credentials.rs`, `mcp_oauth.rs`,
/// `mcp_permissions_v2.rs` — each keeps its own copy rather than sharing one
/// through `common`.
fn allow_private_urls() {
    unsafe { std::env::set_var("MCP_ALLOW_PRIVATE_URLS", "true") };
}
fn disallow_private_urls() {
    unsafe { std::env::remove_var("MCP_ALLOW_PRIVATE_URLS") };
}

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

/// `chk_connectors_provider_fields`'s `system` clause requires `url IS NOT
/// NULL` — a system connector's whole point is a real loopback address, never
/// the "not yet built" NULL a `source_kind='uploaded_build'` row can have.
#[tokio::test]
#[serial]
async fn a_system_connector_row_with_null_url_is_rejected() {
    let server = TestServer::start().await;

    let result = sqlx::query(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type) \
         VALUES ('system', 'system', 'workspace-null-url', NULL, 'none')",
    )
    .execute(&server.db)
    .await;

    assert!(
        result.is_err(),
        "a system row with NULL url must violate chk_connectors_provider_fields"
    );

    server.cleanup().await;
}

/// The same clause requires `auth_type IS NOT DISTINCT FROM 'none'` — a
/// system connector is served by the control plane itself with no per-user
/// credential (`credentials::build_server_config` never reaches any other
/// auth_type arm for one), so any other value must be rejected.
#[tokio::test]
#[serial]
async fn a_system_connector_row_with_bearer_auth_type_is_rejected() {
    let server = TestServer::start().await;

    let result = sqlx::query(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type) \
         VALUES ('system', 'system', 'workspace-bearer-auth', 'http://127.0.0.1:1/mcp', 'bearer')",
    )
    .execute(&server.db)
    .await;

    let err = result.expect_err(
        "a system row with auth_type='bearer' must violate chk_connectors_provider_fields",
    );
    assert!(
        err.to_string().contains("chk_connectors_provider_fields"),
        "error must name the violated constraint: {err}"
    );

    server.cleanup().await;
}

/// `auth_type IS NOT DISTINCT FROM 'none'` (not a bare `=`) is exactly what
/// makes a NULL `auth_type` fail too: `NULL IS NOT DISTINCT FROM 'none'`
/// evaluates to FALSE (unlike `NULL = 'none'`, which evaluates to NULL and
/// would let the row pass a CHECK). This is the migration's whole point — the
/// bearer test above only proves *some* non-'none' value is rejected; this
/// proves the NULL case the `IS NOT DISTINCT FROM` rewrite specifically exists
/// for is rejected too.
#[tokio::test]
#[serial]
async fn a_system_connector_row_with_null_auth_type_is_rejected() {
    let server = TestServer::start().await;

    let result = sqlx::query(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type) \
         VALUES ('system', 'system', 'workspace-null-auth-type', 'http://127.0.0.1:1/mcp', NULL)",
    )
    .execute(&server.db)
    .await;

    let err = result
        .expect_err("a system row with NULL auth_type must violate chk_connectors_provider_fields");
    assert!(
        err.to_string().contains("chk_connectors_provider_fields"),
        "error must name the violated constraint: {err}"
    );

    server.cleanup().await;
}

/// The `system` clause also requires `source_kind::text = 'system'` — ties the
/// two columns together so a `provider_type='system'` row can't pair with, say,
/// `source_kind='external_url'` (a combination nothing else in the schema rules
/// out on its own, since `source_kind='external_url'` is otherwise valid for
/// `provider_type='mcp_server'`).
#[tokio::test]
#[serial]
async fn a_system_connector_row_with_external_url_source_kind_is_rejected() {
    let server = TestServer::start().await;

    let result = sqlx::query(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type) \
         VALUES ('system', 'external_url', 'workspace-wrong-source-kind', 'http://127.0.0.1:1/mcp', 'none')",
    )
    .execute(&server.db)
    .await;

    let err = result.expect_err(
        "a system row with source_kind='external_url' must violate chk_connectors_provider_fields",
    );
    assert!(
        err.to_string().contains("chk_connectors_provider_fields"),
        "error must name the violated constraint: {err}"
    );

    server.cleanup().await;
}

// ─── End-to-end: a system connector through the real gateway ──────────────

async fn seed_user(server: &TestServer, name: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO users (username, email) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(format!("{name}@test.local"))
        .fetch_one(&server.db)
        .await
        .expect("seed user")
}

async fn seed_agent(server: &TestServer, owner_id: Uuid, name: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO agents (name, owner_id, image, status) \
         VALUES ($1, $2, 'nasiko/echo:1.0.0', 'running') RETURNING id",
    )
    .bind(name)
    .bind(owner_id)
    .fetch_one(&server.db)
    .await
    .expect("seed agent")
}

/// Names of the two tools the stub system backend advertises.
const SAVE_FILE: &str = "save_file";
const LIST_FILES: &str = "list_files";

/// The `mcp_connectors.instructions` column's value — the source of truth the
/// gateway must forward. Deliberately different from
/// [`STUB_LIVE_INITIALIZE_INSTRUCTIONS`] below so the assertion can't pass by
/// coincidence.
const DB_INSTRUCTIONS: &str = "WS-E2E-INSTR-FROM-DB-COLUMN";

/// What the stub backend's own live `initialize` response advertises — never
/// what the gateway is supposed to forward (`connector.instructions`, harvested
/// once at registration/probe time, is the source of truth; the gateway never
/// re-probes a system backend's `initialize` per request).
const STUB_LIVE_INITIALIZE_INSTRUCTIONS: &str = "WS-E2E-INSTR-FROM-STUB-LIVE-INITIALIZE";

/// Tracks every `tools/call` the stub backend actually received, by tool name.
type CallLog = Arc<Mutex<Vec<String>>>;

/// Every request the stub backend received, in arrival order, as `(method,
/// x-nasiko-identity header value)` — lets a test single out, say, "the
/// identity header the stub saw on the `tools/call` for save_file", not just
/// "some header was present somewhere", and separately prove a given method
/// (or a given, differently-configured backend) received none at all.
type HeaderLog = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A real MCP JSON-RPC backend standing in for a platform-owned system
/// connector: answers `initialize` with a fixed `instructions` string,
/// `tools/list` with `save_file`/`list_files`, and records every `tools/call`
/// plus every request's `x-nasiko-identity` header (present or not — this
/// same stub also stands in for a NON-system backend later in this file,
/// where the absence is exactly what's being proved). Same shape as
/// `mcp_e2e_agent_flow.rs::start_stub_mcp_backend` — a `provider_type='system'`
/// connector is `trusted` (see `credentials::build_server_config`), so its
/// calls bypass the SSRF guard entirely regardless of URL; unlike that file's
/// test, no `MCP_ALLOW_PRIVATE_URLS` / `allow_private_urls()` dance is needed
/// for the *system* connector below, because this test never goes through the
/// guarded connector-registration HTTP route (`POST /api/mcp/connectors`) for
/// it — the row is inserted directly by SQL, exactly as the platform itself
/// would create one. The non-system connector added later in this file DOES
/// need that dance, same as `mcp_e2e_agent_flow.rs`, since it's an ordinary
/// (untrusted) generic connector.
async fn start_stub_system_backend() -> (String, CallLog, HeaderLog) {
    let calls: CallLog = Arc::new(Mutex::new(Vec::new()));
    let header_log: HeaderLog = Arc::new(Mutex::new(Vec::new()));

    async fn handle(
        State((calls, header_log)): State<(CallLog, HeaderLog)>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        let method = body
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        let identity = headers
            .get(nasiko_mcp_gateway::identity::IDENTITY_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        header_log.lock().unwrap().push((method.clone(), identity));

        match method.as_str() {
            "initialize" => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "serverInfo": {"name": "workspace-stub", "version": "1.0"},
                    "instructions": STUB_LIVE_INITIALIZE_INSTRUCTIONS,
                },
            })),
            "tools/list" => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": {
                    "tools": [
                        {"name": SAVE_FILE, "description": "save a file", "inputSchema": {"type": "object"}},
                        {"name": LIST_FILES, "description": "list files", "inputSchema": {"type": "object"}},
                    ]
                },
            })),
            "tools/call" => {
                let name = body["params"]["name"].as_str().unwrap_or("").to_string();
                calls.lock().unwrap().push(name.clone());
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {"content": [{"type": "text", "text": format!("stub executed '{name}'")}]},
                }))
            }
            other => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": {"code": -32601, "message": format!("stub: method not found: {other}")},
            })),
        }
    }

    let app = Router::new()
        .route("/mcp", post(handle))
        .with_state((calls.clone(), header_log.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://127.0.0.1:{port}/mcp"), calls, header_log)
}

/// Task 1.3/1.9's actual acceptance test: a `provider_type='system'`
/// connector — the synced catalog (`mcp_connector_tools`), a public grant,
/// and a per-agent access row, all inserted exactly as the platform itself
/// would (via SQL, not the connector-registration API, which rejects any
/// `provider_type` other than `mcp_server` — see `net.rs`'s and
/// `types.rs`'s `trusted` doc comments) — driven through the real
/// `/api/mcp` gateway exactly as a deployed agent would: its gateway
/// bearer token plus the traceparent of a live flow it participates in.
#[tokio::test]
#[serial]
async fn system_connector_end_to_end_through_the_real_gateway() {
    // The default test config's `mcp_tool_search_mode` (`""`) parses to
    // `ToolSearchMode::Semantic` (`config::ToolSearchMode::parse`'s fallback
    // for an unrecognized value) — under which `tools/list` returns only
    // search-index matches plus the `nasiko_search_tools` meta-tool, never
    // the full manifest (`protocol::handle_tools_list`). This test asserts
    // the literal bare tool-name set the manifest carries, so it needs the
    // legacy eager-fan-out path; disable search explicitly, the same
    // `TestServer::start_with` override mechanism
    // `mcp_session_grant_stability.rs` uses for its own `McpConfig`.
    let server = TestServer::start_with(|cfg| {
        cfg.mcp_tool_search_mode = "none".to_string();
    })
    .await;

    let owner = seed_user(&server, "ws-e2e-owner").await;
    let agent_id = seed_agent(&server, owner, "ws-e2e-agent").await;

    let (backend_url, backend_calls, backend_headers) = start_stub_system_backend().await;

    let connector_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type, instructions) \
         VALUES ('system', 'system', 'workspace-e2e-connector', $1, 'none', $2) \
         RETURNING id",
    )
    .bind(&backend_url)
    .bind(DB_INSTRUCTIONS)
    .fetch_one(&server.db)
    .await
    .expect("insert system connector");

    sqlx::query(
        "INSERT INTO mcp_connector_grants (connector_id, grant_type, grantee_id) \
         VALUES ($1, 'public', '*')",
    )
    .bind(connector_id)
    .execute(&server.db)
    .await
    .expect("insert public grant");

    for tool in [SAVE_FILE, LIST_FILES] {
        sqlx::query("INSERT INTO mcp_connector_tools (connector_id, tool_name) VALUES ($1, $2)")
            .bind(connector_id)
            .bind(tool)
            .execute(&server.db)
            .await
            .expect("insert synced connector tool");
    }

    sqlx::query(
        "INSERT INTO mcp_agent_connector_access (agent_id, connector_id, enabled) \
         VALUES ($1, $2, true)",
    )
    .bind(agent_id)
    .bind(connector_id)
    .execute(&server.db)
    .await
    .expect("insert agent connector access");

    let token = common::mint_gateway_token(&server.db, agent_id).await;
    let (flow_id, traceparent) = common::open_flow(&server.db, owner, agent_id).await;

    let mcp = |body: Value| {
        server
            .client
            .post(server.url("/api/mcp"))
            .bearer_auth(&token)
            .header("traceparent", &traceparent)
            .json(&body)
    };

    // ── initialize: the DB column's instructions ride along, never the stub's
    //    own live `initialize` response — the gateway forwards what was
    //    harvested into `mcp_connectors.instructions` at registration/probe
    //    time, not a live re-probe of the backend.
    let res = mcp(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let instructions = body["result"]["instructions"].as_str().unwrap_or_default();
    assert!(
        instructions.contains(DB_INSTRUCTIONS),
        "initialize must forward the connector row's DB instructions: {body:?}"
    );
    assert!(
        !instructions.contains(STUB_LIVE_INITIALIZE_INSTRUCTIONS),
        "initialize must never forward the stub's own live `initialize` instructions \
         — the DB column is the source of truth: {body:?}"
    );

    // ── tools/list: exactly the two synced tools, bare (no connector prefix) ──
    let res = mcp(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    let tools = body["result"]["tools"].as_array().expect("tools array");
    let mut names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![LIST_FILES, SAVE_FILE],
        "tools/list must carry exactly the synced catalog's tools, un-namespaced: {body:?}"
    );

    // ── tools/call save_file: reaches the stub, by its bare name ────────────
    let res = mcp(json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": SAVE_FILE, "arguments": {}},
    }))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(
        body.get("error").is_none(),
        "save_file call must not error: {body:?}"
    );
    assert_eq!(
        backend_calls.lock().unwrap().as_slice(),
        &[SAVE_FILE.to_string()],
        "the stub must have recorded exactly one tools/call, for save_file"
    );

    // ── prove the identity header on the wire: the save_file `tools/call`
    //    the stub just logged must carry a header this test can verify with
    //    the same key `Config` derives (`test_config`'s `Config` literal sets
    //    `mcp_identity_signing_key` directly to `TEST_JWT_SECRET`, bypassing
    //    `Config::from_env`'s own JWT_SECRET-derivation — see that field's
    //    doc comment in `oss/server/tests/common/mod.rs`), and it must name
    //    exactly this call's agent, this flow's user, and this flow's trace id.
    let identity_header = {
        let logged = backend_headers.lock().unwrap();
        let (_, header) = logged
            .iter()
            .find(|(method, _)| method == "tools/call")
            .expect("stub must have logged the tools/call request");
        header
            .clone()
            .expect("a system backend must receive x-nasiko-identity on tools/call")
    };
    let verified = nasiko_mcp_gateway::identity::SignedIdentity::verify(
        &identity_header,
        common::TEST_JWT_SECRET.as_bytes(),
    )
    .expect("the gateway's own signature must verify with the test signing key");
    assert_eq!(verified.agent_id, agent_id);
    assert_eq!(verified.user_id, owner);
    assert_eq!(
        verified.flow_id.as_deref(),
        Some(flow_id.as_str()),
        "the signed identity must carry this flow's own trace id"
    );

    // ── tools/call COMPOSIO_SEARCH_TOOLS: never reaches this stub ───────────
    let res = mcp(json!({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "COMPOSIO_SEARCH_TOOLS", "arguments": {}},
    }))
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200, "JSON-RPC errors are still HTTP 200");
    assert_eq!(
        backend_calls.lock().unwrap().as_slice(),
        &[SAVE_FILE.to_string()],
        "the stub's call log must be unchanged — a Composio meta-tool name \
         must never reach the system backend, whatever error the gateway \
         itself returns for it"
    );

    // ── the identity header must never reach a NON-system backend ───────────
    // Same stub implementation, registered as an ordinary (untrusted)
    // `provider_type='mcp_server'` connector this time — proves the header is
    // bound to `server.system`, not to "any backend this test happens to
    // control". An ordinary connector isn't `trusted` (see
    // `credentials::build_server_config`), so its loopback URL needs the same
    // `MCP_ALLOW_PRIVATE_URLS` escape hatch `mcp_e2e_agent_flow.rs` uses.
    //
    // A second agent (not `agent_id`) drives this call, on its own gateway
    // token and its own live flow — deliberately, not a reuse of `agent_id`'s:
    // `load_permission_context` is Redis-cached per agent
    // (`permissions::load_permission_context`), and `agent_id`'s context was
    // already cached by the calls above, before this connector's access row
    // existed. A fresh agent means a fresh cache key, so this assertion can't
    // pass or fail on cache staleness either way.
    allow_private_urls();
    let (non_system_url, non_system_calls, non_system_headers) = start_stub_system_backend().await;

    let non_system_connector_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type) \
         VALUES ('mcp_server', 'external_url', 'ws-e2e-non-system-connector', $1, 'none') \
         RETURNING id",
    )
    .bind(&non_system_url)
    .fetch_one(&server.db)
    .await
    .expect("insert non-system connector");

    sqlx::query(
        "INSERT INTO mcp_connector_grants (connector_id, grant_type, grantee_id) \
         VALUES ($1, 'public', '*')",
    )
    .bind(non_system_connector_id)
    .execute(&server.db)
    .await
    .expect("insert public grant for non-system connector");

    let non_system_agent_id = seed_agent(&server, owner, "ws-e2e-non-system-agent").await;
    sqlx::query(
        "INSERT INTO mcp_agent_connector_access (agent_id, connector_id, enabled) \
         VALUES ($1, $2, true)",
    )
    .bind(non_system_agent_id)
    .bind(non_system_connector_id)
    .execute(&server.db)
    .await
    .expect("insert agent connector access for non-system connector");

    let non_system_token = common::mint_gateway_token(&server.db, non_system_agent_id).await;
    let (_, non_system_traceparent) =
        common::open_flow(&server.db, owner, non_system_agent_id).await;
    let non_system_prefix = nasiko_mcp_gateway::types::connector_prefix(non_system_connector_id);
    let res = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&non_system_token)
        .header("traceparent", &non_system_traceparent)
        .json(&json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": {"name": format!("{non_system_prefix}__{SAVE_FILE}"), "arguments": {}},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    let body: Value = res.json().await.unwrap();
    assert!(
        body.get("error").is_none(),
        "the non-system connector's namespaced tools/call must not error: {body:?}"
    );
    assert_eq!(
        non_system_calls.lock().unwrap().as_slice(),
        &[SAVE_FILE.to_string()],
        "the non-system stub must have recorded the call"
    );
    let non_system_identity = {
        let logged = non_system_headers.lock().unwrap();
        let (_, header) = logged
            .iter()
            .find(|(method, _)| method == "tools/call")
            .expect("non-system stub must have logged the tools/call request");
        header.clone()
    };
    assert!(
        non_system_identity.is_none(),
        "a non-system backend must never receive x-nasiko-identity: {non_system_identity:?}"
    );
    disallow_private_urls();

    server.cleanup().await;
}

/// The regression Task 1.4's review caught: on the gateway's owner-fallback
/// path (`oss/server/src/mcp/handlers/gateway.rs::dispatch`) — reached here by
/// a `tools/list` whose `traceparent` is syntactically well-formed (passes
/// `FlowContext::from_traceparent`'s shape check) but names no row in `flows`
/// at all — the identity signed for the system backend must carry `flow_id:
/// None`, never the bogus trace id lifted from that unverified header. Before
/// the fix, `handle_request` re-parsed the raw `traceparent` itself and would
/// have signed that trace id as if it had been verified.
///
/// `tools/list` (unlike `tools/call`) is exempt from the flow requirement —
/// rule 2 in `mcp_gateway_auth.rs`'s doc comment — so this must return 200
/// via the owner-fallback, not 403.
#[tokio::test]
#[serial]
async fn owner_fallback_tools_list_with_a_bogus_traceparent_signs_flow_id_none() {
    let server = TestServer::start_with(|cfg| {
        cfg.mcp_tool_search_mode = "none".to_string();
    })
    .await;

    let owner = seed_user(&server, "ws-owner-fallback-owner").await;
    let agent_id = seed_agent(&server, owner, "ws-owner-fallback-agent").await;

    let (backend_url, _backend_calls, backend_headers) = start_stub_system_backend().await;

    let connector_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_connectors (provider_type, source_kind, name, url, auth_type, instructions) \
         VALUES ('system', 'system', 'ws-owner-fallback-connector', $1, 'none', 'instr') \
         RETURNING id",
    )
    .bind(&backend_url)
    .fetch_one(&server.db)
    .await
    .expect("insert system connector");

    sqlx::query(
        "INSERT INTO mcp_connector_grants (connector_id, grant_type, grantee_id) \
         VALUES ($1, 'public', '*')",
    )
    .bind(connector_id)
    .execute(&server.db)
    .await
    .expect("insert public grant");

    for tool in [SAVE_FILE, LIST_FILES] {
        sqlx::query("INSERT INTO mcp_connector_tools (connector_id, tool_name) VALUES ($1, $2)")
            .bind(connector_id)
            .bind(tool)
            .execute(&server.db)
            .await
            .expect("insert synced connector tool");
    }

    sqlx::query(
        "INSERT INTO mcp_agent_connector_access (agent_id, connector_id, enabled) \
         VALUES ($1, $2, true)",
    )
    .bind(agent_id)
    .bind(connector_id)
    .execute(&server.db)
    .await
    .expect("insert agent connector access");

    let token = common::mint_gateway_token(&server.db, agent_id).await;

    // Well-formed (32 hex trace id, 16 hex parent id — passes
    // `FlowContext::from_traceparent`'s shape check) but names no row in
    // `flows` at all: `flow_user` must reject it, forcing the owner-fallback
    // path for this read-only method.
    let bogus_traceparent = format!("00-{}-{}-01", "b".repeat(32), "c".repeat(16));

    let res = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("traceparent", &bogus_traceparent)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        res.status(),
        200,
        "tools/list must succeed via the owner-fallback path even though the \
         traceparent doesn't resolve to a live flow"
    );

    let identity_header = {
        let logged = backend_headers.lock().unwrap();
        let (_, header) = logged
            .iter()
            .find(|(method, _)| method == "tools/list")
            .expect("stub must have logged the tools/list request");
        header
            .clone()
            .expect("system backend must receive x-nasiko-identity on tools/list too")
    };
    let verified = nasiko_mcp_gateway::identity::SignedIdentity::verify(
        &identity_header,
        common::TEST_JWT_SECRET.as_bytes(),
    )
    .expect("the gateway's own signature must verify with the test signing key");
    assert_eq!(verified.agent_id, agent_id);
    assert_eq!(
        verified.user_id, owner,
        "the owner-fallback path's user is the agent's owner"
    );
    assert_eq!(
        verified.flow_id, None,
        "the owner-fallback path must sign flow_id: None, never the bogus \
         trace id lifted from an unverified traceparent"
    );

    server.cleanup().await;
}

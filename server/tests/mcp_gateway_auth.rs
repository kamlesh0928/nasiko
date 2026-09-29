//! `POST /api/mcp` auth — deploy-time agent credential + flow-bound user
//! identity (docs/MCP_GATEWAY_AGENT_AUTH.md §2.4).
//!
//! This route is deliberately NOT behind `require_auth`: a deployed agent
//! never holds the calling user's real session JWT (`agent_proxy.rs` strips
//! `Authorization`/`Cookie` before forwarding to a container on purpose). Its
//! only credential is its own `MCP_GATEWAY_TOKEN` (`Authorization: Bearer`),
//! and the user half is resolved server-side from the request's `traceparent`
//! via the `flows` row + `flow_participants` check. These tests lock in every
//! rule of the authorization ladder, each failing closed.

mod common;

use common::TestServer;
use serial_test::serial;
use uuid::Uuid;

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

fn rpc(method: &str) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method,
        "params": {"name": "some__tool", "arguments": {}}})
}

async fn post_mcp(
    server: &TestServer,
    bearer: Option<&str>,
    traceparent: Option<&str>,
    body: &serde_json::Value,
) -> reqwest::Response {
    let mut req = server.client.post(server.url("/api/mcp")).json(body);
    if let Some(t) = bearer {
        req = req.bearer_auth(t);
    }
    if let Some(tp) = traceparent {
        req = req.header("traceparent", tp);
    }
    req.send().await.unwrap()
}

// ─── Rule 1: agent authentication (401s) ─────────────────────────────────────

#[tokio::test]
#[serial]
async fn valid_gateway_token_is_accepted_for_initialize() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-1").await;
    let agent = seed_agent(&server, owner, "gw-agent-1").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(&server, Some(&token), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "MCP Gateway");

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn missing_bearer_is_401() {
    let server = TestServer::start().await;
    let res = post_mcp(&server, None, None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn unknown_or_garbage_tokens_are_401_not_500() {
    let server = TestServer::start().await;
    for bad in ["", "not-a-token", "ngt_deadbeef", &"A".repeat(5000)] {
        let res = post_mcp(&server, Some(bad), None, &rpc("initialize")).await;
        assert_eq!(res.status(), 401, "{bad:?} must be a clean 401");
    }
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn revoked_token_is_401() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-rev").await;
    let agent = seed_agent(&server, owner, "gw-agent-rev").await;
    let token = common::mint_gateway_token(&server.db, agent).await;
    nasiko_mcp_gateway::agent_tokens::revoke(&server.db, agent)
        .await
        .unwrap();

    let res = post_mcp(&server, Some(&token), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401, "a tombstoned credential must not work");
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn rotation_keeps_the_previous_token_alive_for_the_grace_window() {
    // `mint` runs before the new workload is known to be live. Until the rollout
    // lands, the *old* container is still serving with the *old* plaintext, so
    // rejecting it immediately turns a slow or failed deploy into a wave of 401s
    // from a healthy agent (ROTATION_GRACE_SECS).
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-rot").await;
    let agent = seed_agent(&server, owner, "gw-agent-rot").await;
    let old = common::mint_gateway_token(&server.db, agent).await;
    let new = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(&server, Some(&new), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 200, "the freshly minted credential must work");
    let res = post_mcp(&server, Some(&old), None, &rpc("initialize")).await;
    assert_eq!(
        res.status(),
        200,
        "the superseded credential must survive the rollout window"
    );
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn rotation_grace_expires() {
    // Bounded, not indefinite — otherwise redeploy would never actually revoke
    // anything. Age the rotation past the window rather than sleeping through it.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-rot-exp").await;
    let agent = seed_agent(&server, owner, "gw-agent-rot-exp").await;
    let old = common::mint_gateway_token(&server.db, agent).await;
    let new = common::mint_gateway_token(&server.db, agent).await;

    sqlx::query(
        "UPDATE agent_gateway_tokens
         SET rotated_at = now() - make_interval(secs => $2)
         WHERE agent_id = $1",
    )
    .bind(agent)
    .bind((nasiko_mcp_gateway::agent_tokens::ROTATION_GRACE_SECS + 60) as f64)
    .execute(&server.db)
    .await
    .expect("age the rotation");

    let res = post_mcp(&server, Some(&old), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401, "grace must expire");
    let res = post_mcp(&server, Some(&new), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 200, "the current credential is unaffected");
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn revoke_kills_the_grace_credential_too() {
    // Destroy must not leave a second, still-accepted hash behind.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-rot-rev").await;
    let agent = seed_agent(&server, owner, "gw-agent-rot-rev").await;
    let old = common::mint_gateway_token(&server.db, agent).await;
    let new = common::mint_gateway_token(&server.db, agent).await;
    nasiko_mcp_gateway::agent_tokens::revoke(&server.db, agent)
        .await
        .unwrap();

    for (label, token) in [("superseded", &old), ("current", &new)] {
        let res = post_mcp(&server, Some(token), None, &rpc("initialize")).await;
        assert_eq!(res.status(), 401, "{label} credential must be dead");
    }
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn re_minting_for_a_revoked_agent_does_not_resurrect_the_old_credential() {
    // A revoked hash must never be carried into prev_token_hash: destroy
    // tombstoned it, and a later re-mint is a new life, not a continuation.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-rot-res").await;
    let agent = seed_agent(&server, owner, "gw-agent-rot-res").await;
    let destroyed = common::mint_gateway_token(&server.db, agent).await;
    nasiko_mcp_gateway::agent_tokens::revoke(&server.db, agent)
        .await
        .unwrap();
    let reborn = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(&server, Some(&destroyed), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401, "a tombstoned credential stays dead");
    let res = post_mcp(&server, Some(&reborn), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 200);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn soft_deleting_the_agent_kills_its_gateway_token() {
    // `revoke` is best-effort on the destroy path; if it fails, the soft-delete
    // must still close the door. Otherwise a destroyed agent keeps calling tools
    // for as long as any flow it joined stays live.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-del").await;
    let agent = seed_agent(&server, owner, "gw-agent-del").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(&server, Some(&token), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 200, "sanity: live agent authenticates");

    // Soft-delete only — deliberately without calling revoke().
    sqlx::query("UPDATE agents SET deleted_at = now() WHERE id = $1")
        .bind(agent)
        .execute(&server.db)
        .await
        .expect("soft delete");

    let res = post_mcp(&server, Some(&token), None, &rpc("initialize")).await;
    assert_eq!(
        res.status(),
        401,
        "deletion must fail closed even when tombstoning did not run"
    );
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn a_user_session_jwt_is_not_a_gateway_credential() {
    // A real, valid session JWT via Authorization must be rejected: /api/mcp
    // must never silently start trusting user sessions (an agent can never
    // hold one — the proxy strips them by design).
    let server = TestServer::start().await;
    let user_token = common::sign_token(&Uuid::new_v4().to_string(), "someuser", false, "member");
    let res = post_mcp(&server, Some(&user_token), None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401);
    server.cleanup().await;
}

// ─── Rule 2: tools/list works agent-only (no flow required) ──────────────────

#[tokio::test]
#[serial]
async fn tools_list_works_without_a_flow() {
    // Startup-time tool discovery happens outside any flow: agent-only
    // identity (the agent's own connector grants) must be enough for the
    // read-only listing.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-list").await;
    let agent = seed_agent(&server, owner, "gw-agent-list").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(&server, Some(&token), None, &rpc("tools/list")).await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body.get("result").is_some() || body.get("error").is_some(),
        "must be a JSON-RPC response, got: {body}"
    );
    server.cleanup().await;
}

// ─── Rules 3+4: tools/call requires a live flow the agent participates in ────

#[tokio::test]
#[serial]
async fn tools_call_without_traceparent_is_403() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-notp").await;
    let agent = seed_agent(&server, owner, "gw-agent-notp").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(&server, Some(&token), None, &rpc("tools/call")).await;
    assert_eq!(res.status(), 403);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn tools_call_with_unknown_trace_id_is_403() {
    // Presence is not the check — resolution is. A well-formed traceparent
    // naming no flow row must be rejected identically; there is nothing an
    // agent can fabricate to pass.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-unk").await;
    let agent = seed_agent(&server, owner, "gw-agent-unk").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let fabricated = format!("00-{}-00f067aa0ba902b7-01", Uuid::new_v4().simple());
    let res = post_mcp(&server, Some(&token), Some(&fabricated), &rpc("tools/call")).await;
    assert_eq!(res.status(), 403);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn tools_call_from_a_non_participant_agent_is_403() {
    // The attack the participant check exists to stop (§3.3): agent B holds a
    // valid credential of its own and replays a traceparent it observed from
    // agent A's flow — it must not be able to act as that flow's user.
    let server = TestServer::start().await;
    let user = seed_user(&server, "gw-user-np").await;
    let owner = seed_user(&server, "gw-owner-np").await;
    let agent_a = seed_agent(&server, owner, "gw-agent-np-a").await;
    let agent_b = seed_agent(&server, owner, "gw-agent-np-b").await;
    let (_, traceparent) = common::open_flow(&server.db, user, agent_a).await;
    let token_b = common::mint_gateway_token(&server.db, agent_b).await;

    let res = post_mcp(
        &server,
        Some(&token_b),
        Some(&traceparent),
        &rpc("tools/call"),
    )
    .await;
    assert_eq!(res.status(), 403);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn tools_call_on_a_completed_flow_is_403() {
    // Liveness comes from the flow row itself: once complete_flow closes it,
    // the trace id stops authorizing calls (instant revocation).
    let server = TestServer::start().await;
    let user = seed_user(&server, "gw-user-done").await;
    let owner = seed_user(&server, "gw-owner-done").await;
    let agent = seed_agent(&server, owner, "gw-agent-done").await;
    let (flow_id, traceparent) = common::open_flow(&server.db, user, agent).await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    sqlx::query("UPDATE flows SET status = 'completed', completed_at = now() WHERE flow_id = $1")
        .bind(&flow_id)
        .execute(&server.db)
        .await
        .unwrap();

    let res = post_mcp(
        &server,
        Some(&token),
        Some(&traceparent),
        &rpc("tools/call"),
    )
    .await;
    assert_eq!(res.status(), 403);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn tools_call_inside_a_live_flow_passes_the_auth_gate() {
    // The full happy path through the gate: agent credential + live flow +
    // participant record. With no connectors configured the protocol layer
    // answers with a JSON-RPC error object — but over HTTP 200: authorization
    // succeeded and the request reached protocol handling.
    let server = TestServer::start().await;
    let user = seed_user(&server, "gw-user-ok").await;
    let owner = seed_user(&server, "gw-owner-ok").await;
    let agent = seed_agent(&server, owner, "gw-agent-ok").await;
    let (_, traceparent) = common::open_flow(&server.db, user, agent).await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp(
        &server,
        Some(&token),
        Some(&traceparent),
        &rpc("tools/call"),
    )
    .await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body.get("result").is_some() || body.get("error").is_some(),
        "must be a JSON-RPC response, got: {body}"
    );
    server.cleanup().await;
}

// ─── Coding-agent owner policy (spec §16 A3) ─────────────────────────────────
//
// A local coding agent (Claude Code / Codex / OpenCode, connected by the CLI)
// is never dispatched through the proxy, so it never has a flow — `flow_user`
// always fails for it. Its row is stamped `coding_agent_integration_id`, the
// same predicate the LLM router uses (`oss/llm-router/src/resolver/mod.rs`)
// to bill such calls to the owner with no flow; the gateway must resolve the
// same rows to their owner so the two can never disagree. Every other
// flow-less `tools/call` (a plain deployed agent) stays 403 — the policy is
// narrow, keyed only on the column the platform itself sets.

#[tokio::test]
#[serial]
async fn coding_agent_row_without_flow_resolves_to_owner_for_tools_call() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-coding").await;
    let agent_id = seed_agent(&server, owner, "gw-agent-coding").await;
    sqlx::query("UPDATE agents SET coding_agent_integration_id = 'claude' WHERE id = $1")
        .bind(agent_id)
        .execute(&server.db)
        .await
        .unwrap();
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    // No traceparent, tools/call: a coding-agent row is admitted to the
    // protocol layer, which answers the bogus tool name with a JSON-RPC
    // error — but over HTTP 200, same "reached protocol handling" signal as
    // `tools_call_inside_a_live_flow_passes_the_auth_gate` above.
    let res = post_mcp(&server, Some(&token), None, &rpc("tools/call")).await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body.get("error").is_some(),
        "unknown tool must be a JSON-RPC error, got {body}"
    );

    // A plain deployed agent (no coding_agent_integration_id) is still refused.
    let other = seed_agent(&server, owner, "gw-agent-deployed").await;
    let other_token = common::mint_gateway_token(&server.db, other).await;
    let res = post_mcp(&server, Some(&other_token), None, &rpc("tools/call")).await;
    assert_eq!(res.status(), 403);

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn soft_deleted_coding_agent_row_is_not_admitted() {
    // A soft-deleted coding-agent row must not be waved through by the owner
    // policy. In practice this is caught one layer up: `agent_tokens::authenticate`
    // (rule 1) joins on `agents.deleted_at IS NULL`, so a deleted agent's
    // gateway token stops authenticating at all — the request never reaches
    // `dispatch`'s coding-agent-owner branch to begin with. `coding_agent_owner`
    // itself repeats the same `deleted_at IS NULL` filter (see its doc comment
    // in `gateway.rs`) as a second, independent safeguard, exactly like
    // `agent_owner`'s pre-existing one — this test locks in the outcome that
    // safeguard exists for, at the only layer an external test can observe it.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-coding-del").await;
    let agent_id = seed_agent(&server, owner, "gw-agent-coding-del").await;
    sqlx::query("UPDATE agents SET coding_agent_integration_id = 'claude' WHERE id = $1")
        .bind(agent_id)
        .execute(&server.db)
        .await
        .unwrap();
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let res = post_mcp(&server, Some(&token), None, &rpc("tools/call")).await;
    assert_eq!(
        res.status(),
        200,
        "sanity: live coding-agent row is admitted"
    );

    sqlx::query("UPDATE agents SET deleted_at = now() WHERE id = $1")
        .bind(agent_id)
        .execute(&server.db)
        .await
        .expect("soft delete");

    let res = post_mcp(&server, Some(&token), None, &rpc("tools/call")).await;
    assert_eq!(
        res.status(),
        401,
        "a soft-deleted coding-agent row's token must stop authenticating, \
         not fall through to the owner policy"
    );

    server.cleanup().await;
}

// ─── URL-credential form: POST /api/mcp/s/{token} ────────────────────────────
//
// Same credential, same ladder — only the transport differs. These exist to
// prove the URL form is not a weaker door: whatever the header form rejects,
// this must reject identically. The reason it exists at all is that MCP has no
// `OPENAI_API_KEY`-style env convention, so framework clients that expose only
// a `url` have nowhere to put a bearer header.

async fn post_mcp_url(
    server: &TestServer,
    token: &str,
    traceparent: Option<&str>,
    body: &serde_json::Value,
) -> reqwest::Response {
    let mut req = server
        .client
        .post(server.url(&format!("/api/mcp/s/{token}")))
        .json(body);
    if let Some(tp) = traceparent {
        req = req.header("traceparent", tp);
    }
    req.send().await.unwrap()
}

#[tokio::test]
#[serial]
async fn url_credential_is_accepted_for_initialize() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gwu-owner-1").await;
    let agent = seed_agent(&server, owner, "gwu-agent-1").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp_url(&server, &token, None, &rpc("initialize")).await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert_eq!(body["result"]["serverInfo"]["name"], "MCP Gateway");

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn url_credential_unknown_token_is_401() {
    let server = TestServer::start().await;
    let res = post_mcp_url(&server, "ngt_not_a_real_token", None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn url_credential_honours_revocation() {
    // Revocation must reach both forms — they read one row.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gwu-owner-rev").await;
    let agent = seed_agent(&server, owner, "gwu-agent-rev").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    sqlx::query("UPDATE agent_gateway_tokens SET revoked_at = now() WHERE agent_id = $1")
        .bind(agent)
        .execute(&server.db)
        .await
        .expect("revoke");

    let res = post_mcp_url(&server, &token, None, &rpc("initialize")).await;
    assert_eq!(res.status(), 401);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn a_leaked_url_alone_cannot_call_a_tool() {
    // The property that makes carrying the credential in a URL an acceptable
    // trade: the credential proves only *which agent*. Without a traceparent
    // naming a live flow the agent participates in, `tools/call` is still 403 —
    // so a URL scraped from a log or a trace cannot invoke anything.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gwu-owner-leak").await;
    let agent = seed_agent(&server, owner, "gwu-agent-leak").await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp_url(&server, &token, None, &rpc("tools/call")).await;
    assert_eq!(res.status(), 403);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn url_credential_enforces_flow_participation() {
    // Replay of another agent's traceparent is rejected here exactly as it is
    // on the header form.
    let server = TestServer::start().await;
    let user = seed_user(&server, "gwu-user-np").await;
    let owner = seed_user(&server, "gwu-owner-np").await;
    let agent_a = seed_agent(&server, owner, "gwu-agent-np-a").await;
    let agent_b = seed_agent(&server, owner, "gwu-agent-np-b").await;
    let (_, traceparent) = common::open_flow(&server.db, user, agent_a).await;
    let token_b = common::mint_gateway_token(&server.db, agent_b).await;

    let res = post_mcp_url(&server, &token_b, Some(&traceparent), &rpc("tools/call")).await;
    assert_eq!(res.status(), 403);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn url_credential_allows_tools_call_inside_its_own_flow() {
    let server = TestServer::start().await;
    let user = seed_user(&server, "gwu-user-ok").await;
    let owner = seed_user(&server, "gwu-owner-ok").await;
    let agent = seed_agent(&server, owner, "gwu-agent-ok").await;
    let (_, traceparent) = common::open_flow(&server.db, user, agent).await;
    let token = common::mint_gateway_token(&server.db, agent).await;

    let res = post_mcp_url(&server, &token, Some(&traceparent), &rpc("tools/call")).await;
    assert_eq!(res.status(), 200);
    let body: serde_json::Value = res.json().await.unwrap();
    assert!(
        body.get("result").is_some() || body.get("error").is_some(),
        "must be a JSON-RPC response, got: {body}"
    );
    server.cleanup().await;
}

// ─── `MCP-Protocol-Version` header validation ─────────────────────────────────
//
// Task 1.1 made the gateway negotiate `protocolVersion` in `initialize` and
// advertise 2025-06-18. Per the MCP spec, a client that negotiated 2025-06-18
// sends `MCP-Protocol-Version` on every subsequent request; the gateway must
// reject a version it doesn't implement, while still treating the header as
// optional (old clients that never negotiated never send it).

#[tokio::test]
#[serial]
async fn unknown_protocol_version_header_is_rejected_with_400() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-pv").await;
    let agent_id = seed_agent(&server, owner, "pv-agent").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("MCP-Protocol-Version", "1999-01-01")
        .json(&rpc("tools/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("MCP-Protocol-Version", "2025-06-18")
        .json(&rpc("tools/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn missing_protocol_version_header_still_succeeds() {
    // The header is optional — old clients that never negotiated a protocol
    // version never send it, and must not be locked out.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-pv-none").await;
    let agent_id = seed_agent(&server, owner, "pv-agent-none").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .json(&rpc("tools/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn unimplemented_method_probe_is_not_blocked_by_protocol_version_header() {
    // openai-agents, pydantic-ai, and Claude Code's streamable-http clients open
    // a session with a method this gateway doesn't implement (`server/discover`),
    // carrying whatever protocol version they intend to negotiate, and rely on a
    // clean -32601 to trigger their fallback to `initialize`. The header check
    // must not block that first probe just because it names a version we've
    // never negotiated — regression test for the ordering bug in 5ee205ca.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-probe").await;
    let agent_id = seed_agent(&server, owner, "probe-agent").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("MCP-Protocol-Version", "2026-07-28")
        .json(&rpc("server/discover"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"]["code"],
        nasiko_mcp_gateway::types::codes::METHOD_NOT_FOUND,
        "unhandled method must fall through to a clean JSON-RPC -32601, got: {body}"
    );
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn initialize_negotiates_even_with_an_unnegotiated_header_value() {
    // `initialize` is the negotiation request itself — it must never be gated
    // by a header value the client couldn't yet have negotiated. Stronger
    // than "some supported version comes back": the header carries a
    // DIFFERENT (but supported) version than `params.protocolVersion`, so
    // this proves negotiation is driven by params, never by the header.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-init-pv").await;
    let agent_id = seed_agent(&server, owner, "init-pv-agent").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("MCP-Protocol-Version", "2025-06-18")
        .json(
            &serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["result"]["protocolVersion"], "2024-11-05",
        "negotiation must come from params.protocolVersion, not the header: {body}"
    );
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn implemented_method_still_gates_on_protocol_version_header() {
    // The check must still bite where it should: a method the gateway does
    // implement, carrying a version it doesn't.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-gate").await;
    let agent_id = seed_agent(&server, owner, "gate-agent").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("MCP-Protocol-Version", "2026-07-28")
        .json(&rpc("tools/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn undecodable_protocol_version_header_is_400() {
    // A header that fails `to_str()` (not valid visible ASCII) must be
    // rejected outright when the check applies, not silently treated as
    // absent.
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-badenc").await;
    let agent_id = seed_agent(&server, owner, "badenc-agent").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .header("MCP-Protocol-Version", &b"\xff\xfe"[..])
        .json(&rpc("tools/list"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
    server.cleanup().await;
}

// ─── `/api/mcp` body-size limit ────────────────────────────────────────────
//
// The gateway routes raise axum's blanket 2 MiB default to
// `MCP_GATEWAY_MAX_BODY_BYTES` (8 MiB in this test config, matching
// production's default) — see `oss/server/src/mcp/mod.rs::agent_gateway_router`.

fn rpc_padded(method: &str, pad_bytes: usize) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method,
        "params": {"name": "some__tool", "arguments": {}, "pad": "a".repeat(pad_bytes)}})
}

#[tokio::test]
#[serial]
async fn a_body_under_the_raised_limit_is_not_rejected() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-body-ok").await;
    let agent_id = seed_agent(&server, owner, "body-agent-ok").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .json(&rpc_padded("tools/list", 3 * 1024 * 1024))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "a ~3 MiB body must fit under the raised 8 MiB limit — axum's own 2 MiB \
         default would have rejected it"
    );
    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn a_body_over_the_raised_limit_is_413() {
    let server = TestServer::start().await;
    let owner = seed_user(&server, "gw-owner-body-big").await;
    let agent_id = seed_agent(&server, owner, "body-agent-big").await;
    let token = common::mint_gateway_token(&server.db, agent_id).await;

    let resp = server
        .client
        .post(server.url("/api/mcp"))
        .bearer_auth(&token)
        .json(&rpc_padded("tools/list", 9 * 1024 * 1024))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 413);
    server.cleanup().await;
}

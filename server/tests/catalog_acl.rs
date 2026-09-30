//! Integration tests for catalog read-endpoint ACL enforcement and skill-tag dedup.
//!
//! Covers:
//!   - GET /api/agents/{id}       — non-owner gets 403, superuser gets through
//!   - GET /api/agents/{id}/versions — non-owner gets 403
//!   - GET /api/search/agents     — non-owner only sees their own agents
//!   - GET /api/agents, /api/agents/by-skill, /api/search/agents — a public or
//!     user-granted agent (not owned by the caller) is discoverable via listing,
//!     not just fetchable directly by id (CAT-3 regression coverage)
//!   - POST /api/agents           — skill tags are merged into agent.tags on create
//!   - PUT  /api/agents/{id}      — skill tags are merged into agent.tags on update
//!
//! Requires infra (Postgres :5432, Redis, S3):
//!   cargo test -p nasiko-server --test catalog_acl -- --test-threads=1

mod common;

use serde_json::{Value, json};
use serial_test::serial;

// ─── helpers ────────────────────────────────────────────────────────────────

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

async fn create_agent(server: &common::TestServer, uid: &str, body: Value) -> Value {
    let res = common::as_superuser(server.client.post(server.url("/api/agents")), uid, "admin")
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 201, "create agent should succeed");
    res.json::<Value>().await.unwrap()
}

async fn get_agent(
    server: &common::TestServer,
    uid: &str,
    is_super: bool,
    id: &str,
) -> reqwest::Response {
    let rb = server.client.get(server.url(&format!("/api/agents/{id}")));
    if is_super {
        common::as_superuser(rb, uid, "u")
    } else {
        common::as_member(rb, uid, "u")
    }
    .send()
    .await
    .unwrap()
}

async fn list_versions(
    server: &common::TestServer,
    uid: &str,
    is_super: bool,
    agent_id: &str,
) -> reqwest::Response {
    let rb = server
        .client
        .get(server.url(&format!("/api/agents/{agent_id}/versions")));
    if is_super {
        common::as_superuser(rb, uid, "u")
    } else {
        common::as_member(rb, uid, "u")
    }
    .send()
    .await
    .unwrap()
}

async fn search(server: &common::TestServer, uid: &str, is_super: bool, q: &str) -> Vec<Value> {
    let rb = server
        .client
        .get(server.url(&format!("/api/search/agents?q={q}")));
    let res = if is_super {
        common::as_superuser(rb, uid, "u")
    } else {
        common::as_member(rb, uid, "u")
    }
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    // Agent search returns a {agents, total, max_score} envelope (Python parity).
    let body: Value = res.json().await.unwrap();
    body["agents"].as_array().cloned().unwrap_or_default()
}

async fn list_agents(server: &common::TestServer, uid: &str, is_super: bool) -> Vec<Value> {
    let rb = server.client.get(server.url("/api/agents"));
    let res = if is_super {
        common::as_superuser(rb, uid, "u")
    } else {
        common::as_member(rb, uid, "u")
    }
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    res.json::<Vec<Value>>().await.unwrap()
}

async fn by_skill(server: &common::TestServer, uid: &str, is_super: bool, tag: &str) -> Vec<Value> {
    let rb = server
        .client
        .get(server.url(&format!("/api/agents/by-skill?tag={tag}")));
    let res = if is_super {
        common::as_superuser(rb, uid, "u")
    } else {
        common::as_member(rb, uid, "u")
    }
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200);
    res.json::<Vec<Value>>().await.unwrap()
}

/// Insert a direct user-grant row so `grantee_id` can access `agent_id` (CAT-3 tests).
async fn grant_agent_to_user(server: &common::TestServer, agent_id: &str, grantee_id: &str) {
    sqlx::query(
        "INSERT INTO agent_grants (agent_id, grant_type, grantee_id) VALUES ($1, 'user', $2)",
    )
    .bind(uuid::Uuid::parse_str(agent_id).unwrap())
    .bind(grantee_id)
    .execute(&server.db)
    .await
    .unwrap();
}

async fn update_agent(
    server: &common::TestServer,
    uid: &str,
    agent_id: &str,
    body: Value,
) -> Value {
    let res = common::as_superuser(
        server
            .client
            .put(server.url(&format!("/api/agents/{agent_id}"))),
        uid,
        "admin",
    )
    .json(&body)
    .send()
    .await
    .unwrap();
    assert_eq!(res.status(), 200, "update agent should succeed");
    res.json::<Value>().await.unwrap()
}

fn skill(id: &str, tags: &[&str]) -> Value {
    json!({"id": id, "name": format!("{id}-name"), "description": "desc", "tags": tags})
}

// ─── get_one ACL ─────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn get_one_returns_403_for_non_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        uid,
        json!({"name": "acl-get-agent", "version": "1.0.0"}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    let other = create_user(&server, uid, "acl-get-other").await;
    let other_id = other["id"].as_str().unwrap();

    let res = get_agent(&server, other_id, false, agent_id).await;
    assert_eq!(res.status(), 403, "non-owner must get 403 on get_one");

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn get_one_superuser_sees_any_agent() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        uid,
        json!({"name": "acl-super-agent", "version": "1.0.0"}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    // A second superuser can access any agent.
    let other = create_user(&server, uid, "acl-super-other").await;
    let other_id = other["id"].as_str().unwrap();

    let res = get_agent(&server, other_id, true, agent_id).await;
    assert_eq!(res.status(), 200, "superuser must be able to get any agent");

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn get_one_by_name_returns_403_for_non_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    create_agent(
        &server,
        uid,
        json!({"name": "acl-name-agent", "version": "1.0.0"}),
    )
    .await;

    let other = create_user(&server, uid, "acl-name-other").await;
    let other_id = other["id"].as_str().unwrap();

    let res = get_agent(&server, other_id, false, "acl-name-agent").await;
    assert_eq!(
        res.status(),
        403,
        "non-owner must get 403 when looking up agent by name"
    );

    server.cleanup().await;
}

// ─── list_versions ACL ───────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn list_versions_returns_403_for_non_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        uid,
        json!({"name": "acl-versions-agent", "version": "1.0.0"}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    let other = create_user(&server, uid, "acl-versions-other").await;
    let other_id = other["id"].as_str().unwrap();

    let res = list_versions(&server, other_id, false, agent_id).await;
    assert_eq!(res.status(), 403, "non-owner must get 403 on list_versions");

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn list_versions_superuser_sees_any_agent() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        uid,
        json!({"name": "acl-versions-super", "version": "1.0.0"}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    let other = create_user(&server, uid, "acl-vers-super-other").await;
    let other_id = other["id"].as_str().unwrap();

    let res = list_versions(&server, other_id, true, agent_id).await;
    assert_eq!(
        res.status(),
        200,
        "superuser must be able to list versions for any agent"
    );

    server.cleanup().await;
}

// ─── search owner scoping ────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn search_is_owner_scoped() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let other = create_user(&server, uid, "srch-other").await;
    let other_id = other["id"].as_str().unwrap();

    // Admin owns one agent; other user owns a second one (created via admin elevation).
    create_agent(
        &server,
        uid,
        json!({"name": "srch-admin-agent", "version": "1.0.0"}),
    )
    .await;

    let other_agent = common::as_member(
        server.client.post(server.url("/api/agents")),
        other_id,
        "srch-other",
    )
    .json(&json!({"name": "srch-other-agent", "version": "1.0.0"}))
    .send()
    .await
    .unwrap();
    assert_eq!(other_agent.status(), 201);

    // Non-superuser search: only their own agent.
    let results = search(&server, other_id, false, "srch").await;
    let names: Vec<&str> = results.iter().filter_map(|a| a["name"].as_str()).collect();
    assert!(
        names.contains(&"srch-other-agent"),
        "user must see their own agent"
    );
    assert!(
        !names.contains(&"srch-admin-agent"),
        "user must not see other's agent"
    );

    // Superuser search: both agents.
    let all = search(&server, uid, true, "srch").await;
    let all_names: Vec<&str> = all.iter().filter_map(|a| a["name"].as_str()).collect();
    assert!(all_names.contains(&"srch-admin-agent"));
    assert!(all_names.contains(&"srch-other-agent"));

    server.cleanup().await;
}

// ─── CAT-3: listing endpoints must surface public/granted agents ────────────
// `get_one` already allows a non-owner to fetch a public or user-granted agent
// directly by id (see `public_agent_non_owner_can_read_but_not_mutate` above).
// `list`, `by_skill`, and `search` must apply the same owner ∪ public ∪
// user-grant predicate, not a bare owner_id scope — otherwise such an agent is
// fetchable by id but never discoverable by browsing/searching.

#[tokio::test]
#[serial]
async fn list_includes_public_agent_for_non_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let pub_agent = create_agent(
        &server,
        uid,
        json!({"name": "cat3-list-pub", "version": "1.0.0"}),
    )
    .await;
    let pub_id = pub_agent["id"].as_str().unwrap();
    sqlx::query("UPDATE agents SET is_public = true WHERE id = $1")
        .bind(uuid::Uuid::parse_str(pub_id).unwrap())
        .execute(&server.db)
        .await
        .unwrap();

    let priv_agent = create_agent(
        &server,
        uid,
        json!({"name": "cat3-list-priv", "version": "1.0.0"}),
    )
    .await;
    let priv_id = priv_agent["id"].as_str().unwrap();

    let bob = create_user(&server, uid, "cat3-list-bob").await;
    let bob_id = bob["id"].as_str().unwrap();

    let seen = list_agents(&server, bob_id, false).await;
    let ids: Vec<&str> = seen.iter().filter_map(|a| a["id"].as_str()).collect();

    assert!(
        ids.contains(&pub_id),
        "non-owner must see a public agent in the list"
    );
    assert!(
        !ids.contains(&priv_id),
        "non-owner must not see a private, non-granted agent in the list"
    );

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn list_excludes_internal_agent_even_for_superuser() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let internal = create_agent(
        &server,
        uid,
        json!({"name": "cat3-internal-hidden", "version": "1.0.0"}),
    )
    .await;
    let internal_id = internal["id"].as_str().unwrap();
    // Public too — proves the exclusion applies regardless of access rules,
    // not just because it would otherwise have been invisible. `is_internal`
    // isn't exposed through the create/update API by design (an ordinary
    // metadata edit must never be able to flip it), so it's set directly.
    sqlx::query("UPDATE agents SET is_public = true, is_internal = true WHERE id = $1")
        .bind(uuid::Uuid::parse_str(internal_id).unwrap())
        .execute(&server.db)
        .await
        .unwrap();

    let normal = create_agent(
        &server,
        uid,
        json!({"name": "cat3-internal-normal", "version": "1.0.0"}),
    )
    .await;
    let normal_id = normal["id"].as_str().unwrap();

    let seen = list_agents(&server, uid, true).await;
    let ids: Vec<&str> = seen.iter().filter_map(|a| a["id"].as_str()).collect();

    assert!(
        !ids.contains(&internal_id),
        "an internal agent must not appear in the list, even for a superuser"
    );
    assert!(
        ids.contains(&normal_id),
        "an ordinary agent's visibility must be unaffected"
    );

    server.cleanup().await;
}

/// Task 1.6 (spec §16 A4): a coding-agent row is visible ONLY to its own owner, even when marked
/// `is_public` directly — never via `is_public`, a grant, or a superuser's normally-unrestricted
/// view. A listing showing it to anyone else would violate the single-owner precondition Task
/// 1.5's MCP-gateway owner-fallback policy relies on. The owner themselves must still see it,
/// though (the product expectation that a connected coding agent shows in its own owner's list) —
/// unlike `is_internal`, this exclusion is owner-scoped, not absolute.
#[tokio::test]
#[serial]
async fn list_shows_coding_agent_row_only_to_its_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let coding_agent = create_agent(
        &server,
        uid,
        json!({"name": "cat3-coding-owner-only", "version": "1.0.0"}),
    )
    .await;
    let coding_id = coding_agent["id"].as_str().unwrap();
    // `is_public = true` bypasses the write-side guard added in `agents/grants.rs` — this proves
    // the read side (the listing query) is independently defended too, not only the write path.
    sqlx::query(
        "UPDATE agents SET is_public = true, coding_agent_integration_id = 'claude' WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(coding_id).unwrap())
    .execute(&server.db)
    .await
    .unwrap();

    let normal = create_agent(
        &server,
        uid,
        json!({"name": "cat3-coding-normal", "version": "1.0.0"}),
    )
    .await;
    let normal_id = normal["id"].as_str().unwrap();

    let bob = create_user(&server, uid, "cat3-coding-bob").await;
    let bob_id = bob["id"].as_str().unwrap();

    // A second superuser, distinct from the coding row's owner — the general "superuser sees
    // everything" bypass must not extend to a coding-agent row it doesn't own.
    let other_super_id: uuid::Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, is_superuser) VALUES ($1, $2, true) RETURNING id",
    )
    .bind("cat3-coding-other-super")
    .bind("cat3-coding-other-super@test.local")
    .fetch_one(&server.db)
    .await
    .unwrap();

    let owner_seen = list_agents(&server, uid, true).await;
    let owner_ids: Vec<&str> = owner_seen.iter().filter_map(|a| a["id"].as_str()).collect();
    assert!(
        owner_ids.contains(&coding_id),
        "the owner must see their own coding-agent row"
    );
    assert!(
        owner_ids.contains(&normal_id),
        "an ordinary agent's visibility must be unaffected"
    );

    let bob_seen = list_agents(&server, bob_id, false).await;
    let bob_ids: Vec<&str> = bob_seen.iter().filter_map(|a| a["id"].as_str()).collect();
    assert!(
        !bob_ids.contains(&coding_id),
        "a non-owner must not see another user's coding-agent row, even marked public"
    );

    let other_super_seen = list_agents(&server, &other_super_id.to_string(), true).await;
    let other_super_ids: Vec<&str> = other_super_seen
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(
        !other_super_ids.contains(&coding_id),
        "a superuser who does not own the coding-agent row must not see it either"
    );

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn by_skill_includes_user_granted_agent_for_non_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let granted = create_agent(
        &server,
        uid,
        json!({
            "name": "cat3-skill-granted",
            "version": "1.0.0",
            "skills": [skill("cat3-s1", &["cat3-skill-tag"])],
        }),
    )
    .await;
    let granted_id = granted["id"].as_str().unwrap();

    let ungranted = create_agent(
        &server,
        uid,
        json!({
            "name": "cat3-skill-ungranted",
            "version": "1.0.0",
            "skills": [skill("cat3-s2", &["cat3-skill-tag"])],
        }),
    )
    .await;
    let ungranted_id = ungranted["id"].as_str().unwrap();

    let bob = create_user(&server, uid, "cat3-skill-bob").await;
    let bob_id = bob["id"].as_str().unwrap();
    grant_agent_to_user(&server, granted_id, bob_id).await;

    let seen = by_skill(&server, bob_id, false, "cat3-skill-tag").await;
    let ids: Vec<&str> = seen.iter().filter_map(|a| a["id"].as_str()).collect();

    assert!(
        ids.contains(&granted_id),
        "non-owner must see a user-granted agent via by-skill"
    );
    assert!(
        !ids.contains(&ungranted_id),
        "non-owner must not see a non-granted agent via by-skill"
    );

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn by_skill_excludes_internal_agent_even_with_a_matching_skill_tag() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let internal = create_agent(
        &server,
        uid,
        json!({
            "name": "cat3-skill-internal",
            "version": "1.0.0",
            "skills": [skill("cat3-s3", &["cat3-internal-skill-tag"])],
        }),
    )
    .await;
    let internal_id = internal["id"].as_str().unwrap();
    sqlx::query("UPDATE agents SET is_public = true, is_internal = true WHERE id = $1")
        .bind(uuid::Uuid::parse_str(internal_id).unwrap())
        .execute(&server.db)
        .await
        .unwrap();

    let seen = by_skill(&server, uid, true, "cat3-internal-skill-tag").await;
    let ids: Vec<&str> = seen.iter().filter_map(|a| a["id"].as_str()).collect();

    assert!(
        !ids.contains(&internal_id),
        "an internal agent must not appear via by-skill, even for a superuser, even with a matching skill tag"
    );

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn search_includes_public_agent_for_non_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let pub_agent = create_agent(
        &server,
        uid,
        json!({"name": "cat3-search-pub", "version": "1.0.0"}),
    )
    .await;
    let pub_id = pub_agent["id"].as_str().unwrap();
    sqlx::query("UPDATE agents SET is_public = true WHERE id = $1")
        .bind(uuid::Uuid::parse_str(pub_id).unwrap())
        .execute(&server.db)
        .await
        .unwrap();

    create_agent(
        &server,
        uid,
        json!({"name": "cat3-search-priv", "version": "1.0.0"}),
    )
    .await;

    let bob = create_user(&server, uid, "cat3-search-bob").await;
    let bob_id = bob["id"].as_str().unwrap();

    let results = search(&server, bob_id, false, "cat3-search").await;
    let names: Vec<&str> = results.iter().filter_map(|a| a["name"].as_str()).collect();

    assert!(
        names.contains(&"cat3-search-pub"),
        "non-owner must see a public agent via search"
    );
    assert!(
        !names.contains(&"cat3-search-priv"),
        "non-owner must not see a private, non-granted agent via search"
    );

    server.cleanup().await;
}

/// Task 1.6 (spec §16 A4): `search()` used to run `agent_access_predicate` with no
/// `coding_agent_integration_id` filter at all, so a coding-agent row marked `is_public` leaked
/// through search to any caller. Same owner-only visibility rule as `list`/`by_skill`.
#[tokio::test]
#[serial]
async fn search_shows_coding_agent_row_only_to_its_owner() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let coding_agent = create_agent(
        &server,
        uid,
        json!({"name": "cat3-search-coding", "version": "1.0.0"}),
    )
    .await;
    let coding_id = coding_agent["id"].as_str().unwrap();
    sqlx::query(
        "UPDATE agents SET is_public = true, coding_agent_integration_id = 'claude' WHERE id = $1",
    )
    .bind(uuid::Uuid::parse_str(coding_id).unwrap())
    .execute(&server.db)
    .await
    .unwrap();

    let bob = create_user(&server, uid, "cat3-search-coding-bob").await;
    let bob_id = bob["id"].as_str().unwrap();

    let owner_results = search(&server, uid, true, "cat3-search-coding").await;
    let owner_names: Vec<&str> = owner_results
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert!(
        owner_names.contains(&"cat3-search-coding"),
        "the owner must see their own coding-agent row via search"
    );

    let bob_results = search(&server, bob_id, false, "cat3-search-coding").await;
    let bob_names: Vec<&str> = bob_results
        .iter()
        .filter_map(|a| a["name"].as_str())
        .collect();
    assert!(
        !bob_names.contains(&"cat3-search-coding"),
        "a non-owner must not see another user's coding-agent row via search, even marked public"
    );

    server.cleanup().await;
}

// ─── skill-tag dedup ─────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn create_with_skills_merges_skill_tags() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        uid,
        json!({
            "name": "tag-merge-create",
            "version": "1.0.0",
            "tags": ["explicit-tag"],
            "skills": [
                skill("s1", &["nlp", "streaming"]),
                skill("s2", &["nlp", "vision"]),   // "nlp" appears in both skills
            ]
        }),
    )
    .await;

    let tags: Vec<&str> = agent["tags"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.as_str())
        .collect();

    assert!(
        tags.contains(&"explicit-tag"),
        "explicit tag must be preserved"
    );
    assert!(tags.contains(&"nlp"), "skill tag 'nlp' must be included");
    assert!(
        tags.contains(&"streaming"),
        "skill tag 'streaming' must be included"
    );
    assert!(
        tags.contains(&"vision"),
        "skill tag 'vision' must be included"
    );

    let nlp_count = tags.iter().filter(|&&t| t == "nlp").count();
    assert_eq!(nlp_count, 1, "'nlp' must appear exactly once after dedup");

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn update_with_skills_merges_skill_tags() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let uid = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        uid,
        json!({
            "name": "tag-merge-update",
            "version": "1.0.0",
            "tags": ["pre-existing"],
        }),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    let updated = update_agent(
        &server,
        uid,
        agent_id,
        json!({
            "tags": ["pre-existing", "added"],
            "skills": [skill("upd-s1", &["added", "from-skill"])],
        }),
    )
    .await;

    let tags: Vec<&str> = updated["tags"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.as_str())
        .collect();

    assert!(
        tags.contains(&"pre-existing"),
        "pre-existing tag must be preserved"
    );
    assert!(
        tags.contains(&"added"),
        "'added' from both explicit tags and skill must appear once"
    );
    assert!(
        tags.contains(&"from-skill"),
        "skill-only tag must be included"
    );

    let added_count = tags.iter().filter(|&&t| t == "added").count();
    assert_eq!(
        added_count, 1,
        "'added' must appear exactly once after dedup"
    );

    server.cleanup().await;
}

// ─── read vs manage split (R3 correction / RUN-9) ────────────────────────────
// A public (or invoke-granted) agent is READABLE by a non-owner, but must NOT be
// mutable/destroyable by them — mutations are owner-or-superuser only.
#[tokio::test]
#[serial]
async fn public_agent_non_owner_can_read_but_not_mutate() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let owner_id = admin["user_id"].as_str().unwrap();

    let agent = create_agent(
        &server,
        owner_id,
        json!({"name": "pub-split-agent", "version": "1.0.0"}),
    )
    .await;
    let agent_id = agent["id"].as_str().unwrap();

    // Make it public so view-access (can_access_agent) is true for anyone.
    sqlx::query("UPDATE agents SET is_public = true WHERE id = $1")
        .bind(uuid::Uuid::parse_str(agent_id).unwrap())
        .execute(&server.db)
        .await
        .unwrap();

    let bob = create_user(&server, owner_id, "bobpub").await;
    let bob_id = bob["id"].as_str().unwrap();

    // READ: allowed for a non-owner because the agent is public.
    let read = get_agent(&server, bob_id, false, agent_id).await;
    assert_eq!(
        read.status(),
        200,
        "non-owner should be able to read a public agent"
    );

    // DELETE: forbidden — destroy is owner-or-superuser (RUN-9 IDOR guard).
    let del = common::as_member(
        server
            .client
            .delete(server.url(&format!("/api/agents/{agent_id}"))),
        bob_id,
        "bobpub",
    )
    .send()
    .await
    .unwrap();
    assert_eq!(
        del.status(),
        403,
        "non-owner must NOT delete a public agent"
    );

    // UPDATE: likewise forbidden — an invoke/public grant is not a manage grant.
    let upd = common::as_member(
        server
            .client
            .put(server.url(&format!("/api/agents/{agent_id}"))),
        bob_id,
        "bobpub",
    )
    .json(&json!({"description": "hijacked"}))
    .send()
    .await
    .unwrap();
    assert_eq!(
        upd.status(),
        403,
        "non-owner must NOT update a public agent"
    );

    server.cleanup().await;
}

#[tokio::test]
#[serial]
async fn coding_agent_registration_is_server_managed_idempotent_and_conflict_safe() {
    let server = common::TestServer::start().await;
    let admin = init_admin(&server).await;
    let admin_id = admin["user_id"].as_str().unwrap();

    let generic = create_agent(
        &server,
        admin_id,
        json!({
            "name": "admin-claude-code",
            "metadata": {"source": "nasiko-cli-integration", "integration_id": "claude"}
        }),
    )
    .await;
    let generic_id = generic["id"].as_str().unwrap();
    let generic_detail = get_agent(&server, admin_id, true, generic_id)
        .await
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(generic_detail["data"]["is_coding_agent"], false);
    assert!(generic_detail["data"]["coding_agent_integration_id"].is_null());

    let conflict = common::as_superuser(
        server
            .client
            .post(server.url("/api/agents/coding-integrations")),
        admin_id,
        "admin",
    )
    .json(&json!({"integration_id": "claude"}))
    .send()
    .await
    .unwrap();
    assert_eq!(conflict.status(), 409);

    let alice = create_user(&server, admin_id, "Alice_Example").await;
    let alice_id = alice["id"].as_str().unwrap();
    let register = || {
        common::as_member(
            server
                .client
                .post(server.url("/api/agents/coding-integrations")),
            alice_id,
            "Alice_Example",
        )
        .json(&json!({"integration_id": "claude"}))
        .send()
    };
    let first = register().await.unwrap();
    assert_eq!(first.status(), 201);
    let first: Value = first.json().await.unwrap();
    assert_eq!(first["name"], "alice-example-claude-code");
    assert_eq!(first["coding_agent_integration_id"], "claude");
    assert_eq!(first["created"], true);

    let second = register().await.unwrap();
    assert_eq!(second.status(), 200);
    let second: Value = second.json().await.unwrap();
    assert_eq!(second["id"], first["id"]);
    assert_eq!(second["created"], false);

    let unsupported = common::as_member(
        server
            .client
            .post(server.url("/api/agents/coding-integrations")),
        alice_id,
        "Alice_Example",
    )
    .json(&json!({"integration_id": "unknown"}))
    .send()
    .await
    .unwrap();
    assert_eq!(unsupported.status(), 400);

    server.cleanup().await;
}

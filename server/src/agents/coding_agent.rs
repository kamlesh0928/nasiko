//! Shared guard for CLI-bound coding-agent rows (`agents.coding_agent_integration_id IS NOT
//! NULL`).
//!
//! Such a row must stay single-owner and never be dispatched into — the MCP gateway's
//! owner-fallback policy (`oss/server/src/mcp/handlers/gateway.rs`) depends on both holding.
//! Two operations would break that invariant:
//!
//!   - **Sharing** the row via an `agent_grants` insert — a listing would then show it to
//!     someone other than its owner, and a future route-to-local-agent feature would silently
//!     violate the "owner == the only user this row ever resolves to" invariant.
//!   - **Deploying** a container onto the row — every upsert-or-deploy path that keys off
//!     `(owner_id, name)` or an existing `id` keeps `coding_agent_integration_id` as is, so a
//!     deployed container would inherit the owner policy while being dispatchable, which is the
//!     precondition of a participant-laundering chain.
//!
//! Both are rejected here with a 409. The rule: every path that inserts into `agent_grants`,
//! changes `agents.owner_id`, or deploys onto an existing agent row must call one of the
//! functions below before its side effect — in OSS or, wrapping rather than forking this check,
//! in an edition-specific handler.
//!
//! A DB error while answering "is this a coding agent" fails the request closed (500), not open:
//! silently treating an error as "not a coding agent" would let the share/deploy proceed exactly
//! when the check couldn't actually be performed.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::PgPool;
use uuid::Uuid;

/// Which operation is being rejected — picks the wire-visible 409 body. Sharing and (re)deploying
/// fail the same underlying check but get distinct, independently-asserted-on messages.
pub enum CodingAgentGuard {
    /// An `agent_grants` insert: user, team/org-unit, organization, agent-to-agent, or public.
    Unshareable,
    /// A redeploy: an update/rollback/upload/import/admin-deploy/restart path targeting an
    /// existing coding-agent row.
    NotDeployable,
}

impl CodingAgentGuard {
    fn message(&self) -> &'static str {
        match self {
            Self::Unshareable => {
                "coding_agent_unshareable: local coding agents cannot be shared yet; their artifacts can"
            }
            Self::NotDeployable => {
                "coding_agent_not_deployable: local coding agents run on the developer's machine; deploy a separate agent instead"
            }
        }
    }

    /// 409 iff `is_coding_agent` — for a caller that already knows the answer (e.g. from a row it
    /// fetched for its own purposes) and would otherwise pay for the same query
    /// [`reject_if_coding_agent`] runs.
    pub fn reject_if(&self, is_coding_agent: bool) -> Result<(), Response> {
        if is_coding_agent {
            Err((StatusCode::CONFLICT, self.message()).into_response())
        } else {
            Ok(())
        }
    }
}

/// `Ok(true)` for a live (non-soft-deleted) coding-agent row, `Ok(false)` for an ordinary or
/// missing/deleted one — callers needing "does this agent exist at all" have their own existence
/// check already; this only ever needs to answer "is it a coding agent". `Err` on a DB failure —
/// every caller below propagates it rather than silently treating it as `false` (see module doc).
async fn is_coding_agent(db: &PgPool, agent_id: Uuid) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT coding_agent_integration_id IS NOT NULL FROM agents \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(agent_id)
    .fetch_optional(db)
    .await
    .map(|row| row.unwrap_or(false))
}

/// Same check keyed on `(owner_id, name)` instead of `id` — the upload/import/GitHub-deploy
/// upserts' own key (`ON CONFLICT (owner_id, name)`). Needed because those paths must reject
/// *before* the upsert runs, i.e. before there is a resolved `id` for an existing row to check.
async fn is_coding_agent_by_owner_and_name(
    db: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT coding_agent_integration_id IS NOT NULL FROM agents \
         WHERE owner_id = $1 AND name = $2 AND deleted_at IS NULL",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .map(|row| row.unwrap_or(false))
}

/// 409 if `agent_id` names a coding-agent row — call before any mutation that would share or
/// redeploy it. A non-coding-agent row (including a nonexistent one — its own existence check
/// belongs to the caller) passes through untouched. 500 if the check itself fails (see module
/// doc) — this must never fail open.
pub async fn reject_if_coding_agent(
    db: &PgPool,
    agent_id: Uuid,
    guard: CodingAgentGuard,
) -> Result<(), Response> {
    let is_coding = is_coding_agent(db, agent_id).await.map_err(|e| {
        tracing::error!(
            %e, %agent_id,
            "coding_agent guard: db error checking coding_agent_integration_id by id"
        );
        (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
    })?;
    guard.reject_if(is_coding)
}

/// 409 if `(owner_id, name)` already names a coding-agent row — the pre-check every
/// `(owner_id, name)`-keyed upsert (upload, GitHub deploy, catalog import) runs before its own
/// `ON CONFLICT (owner_id, name)` write (see module doc). Always
/// [`CodingAgentGuard::NotDeployable`]: these paths only ever (re)deploy, never share. 500 if the
/// check itself fails, same as [`reject_if_coding_agent`].
pub async fn reject_if_coding_agent_by_owner_and_name(
    db: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<(), Response> {
    let is_coding = is_coding_agent_by_owner_and_name(db, owner_id, name)
        .await
        .map_err(|e| {
            tracing::error!(
                %e, %owner_id, %name,
                "coding_agent guard: db error checking coding_agent_integration_id by (owner_id, name)"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "internal server error").into_response()
        })?;
    CodingAgentGuard::NotDeployable.reject_if(is_coding)
}

/// Same check as [`reject_if_coding_agent_by_owner_and_name`], for a caller whose own error
/// channel is `(StatusCode, String)` rather than a `Response` — `catalog::import::build_and_deploy`
/// isn't an axum handler itself (it's shared by three routes, each converting its `Result` to a
/// response its own way), so it cannot build one.
pub async fn reject_if_coding_agent_by_owner_and_name_tupled(
    db: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<(), (StatusCode, String)> {
    let is_coding = is_coding_agent_by_owner_and_name(db, owner_id, name)
        .await
        .map_err(|e| {
            tracing::error!(
                %e, %owner_id, %name,
                "coding_agent guard: db error checking coding_agent_integration_id by (owner_id, name)"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal error".to_string(),
            )
        })?;
    if is_coding {
        return Err((
            StatusCode::CONFLICT,
            CodingAgentGuard::NotDeployable.message().to_string(),
        ));
    }
    Ok(())
}

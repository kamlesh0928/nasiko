//! Shared guard for CLI-bound coding-agent rows (`agents.coding_agent_integration_id IS NOT
//! NULL`, spec §16 A4).
//!
//! Task 1.5's owner-fallback policy at the MCP gateway (`oss/server/src/mcp/handlers/gateway.rs`)
//! is safe only while such a row stays single-owner and is never dispatched into. Two operations
//! would break that precondition:
//!
//!   - **Sharing** the row via an `agent_grants` insert — a listing would then show it to
//!     someone other than its owner, and a future route-to-local-agent feature would silently
//!     violate the "owner == the only user this row ever resolves to" invariant.
//!   - **Deploying** a container onto the row — `PUT /api/agents/{id}/update`, its rollback path,
//!     and the `nasiko upload` `(owner_id, name)` upsert all keep `coding_agent_integration_id` as
//!     is, so an uploaded/rolled-back container would inherit the owner policy while being
//!     dispatchable, which is the precondition of a participant-laundering chain.
//!
//! Both are rejected here with a 409, from one shared check called by every mutation that could
//! do either: OSS `agents::grants`, `agents::update`, `agents::upload`, and — wrapping, never
//! forking, this OSS check — `ee/server/src/grants.rs`'s own seven `agent_grants`-inserting
//! handlers.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use sqlx::PgPool;
use uuid::Uuid;

/// Which operation is being rejected — picks the wire-visible 409 body. Sharing and (re)deploying
/// fail the same underlying check but get distinct, independently-asserted-on messages.
pub enum CodingAgentGuard {
    /// An `agent_grants` insert: user, team/org-unit, organization, agent-to-agent, or public.
    Unshareable,
    /// A redeploy: `PUT /api/agents/{id}/update`, its rollback path, or the `nasiko upload`
    /// `(owner_id, name)` upsert.
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

/// `true` for a live (non-soft-deleted) coding-agent row. A missing/deleted agent answers
/// `false` — callers needing "does this agent exist at all" have their own existence check
/// already; this only ever needs to answer "is it a coding agent".
async fn is_coding_agent(db: &PgPool, agent_id: Uuid) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT coding_agent_integration_id IS NOT NULL FROM agents \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(agent_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// Same check keyed on `(owner_id, name)` instead of `id` — the upload upsert's own key
/// (`ON CONFLICT (owner_id, name)`). Needed because that path must reject *before* the upsert
/// runs, i.e. before there is a resolved `id` for an existing row to check.
async fn is_coding_agent_by_owner_and_name(db: &PgPool, owner_id: Uuid, name: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT coding_agent_integration_id IS NOT NULL FROM agents \
         WHERE owner_id = $1 AND name = $2 AND deleted_at IS NULL",
    )
    .bind(owner_id)
    .bind(name)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false)
}

/// 409 if `agent_id` names a coding-agent row — call before any mutation that would share or
/// redeploy it. A non-coding-agent row (including a nonexistent one — its own existence check
/// belongs to the caller) passes through untouched.
pub async fn reject_if_coding_agent(
    db: &PgPool,
    agent_id: Uuid,
    guard: CodingAgentGuard,
) -> Result<(), Response> {
    guard.reject_if(is_coding_agent(db, agent_id).await)
}

/// 409 if `(owner_id, name)` already names a coding-agent row — the `nasiko upload` upsert's own
/// pre-check, run before its `ON CONFLICT (owner_id, name)` write (see module doc). Always
/// [`CodingAgentGuard::NotDeployable`]: upload only ever (re)deploys, never shares.
pub async fn reject_if_coding_agent_by_owner_and_name(
    db: &PgPool,
    owner_id: Uuid,
    name: &str,
) -> Result<(), Response> {
    CodingAgentGuard::NotDeployable
        .reject_if(is_coding_agent_by_owner_and_name(db, owner_id, name).await)
}

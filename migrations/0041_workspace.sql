-- 0041_workspace.sql (part 1: system connectors)
ALTER TABLE mcp_connectors DROP CONSTRAINT IF EXISTS mcp_connectors_provider_type_check;
ALTER TABLE mcp_connectors
    ADD CONSTRAINT mcp_connectors_provider_type_check
    CHECK (provider_type IN ('composio', 'mcp_server', 'system'));
-- A platform-owned backend served by the control plane itself (loopback). Exempt from
-- the SSRF guard, tools are exposed un-prefixed, never user-deletable.
ALTER TYPE mcp_connector_source_kind ADD VALUE IF NOT EXISTS 'system';
-- Harvested at probe today but only kept as `description`; instructions need their own column
-- so `initialize` can forward them verbatim.
ALTER TABLE mcp_connectors ADD COLUMN IF NOT EXISTS instructions TEXT;

-- 0003_mcp.sql's chk_connectors_provider_fields only allows the composio/
-- mcp_server field combinations, so a provider_type='system' row (however
-- source_kind/auth_type are set) still cannot be inserted without this.
-- Existing clauses reproduced verbatim; only the trailing `system` clause is
-- new. A system connector is always url-set (loopback address, never NULL
-- pending a build like uploaded_build) and auth_type='none' (no per-user
-- credential — see credentials::build_server_config, which never reaches the
-- other auth_type arms for a provider_type='system' row today; that invariant
-- is enforced here, not just assumed).
ALTER TABLE mcp_connectors DROP CONSTRAINT IF EXISTS chk_connectors_provider_fields;
ALTER TABLE mcp_connectors
    ADD CONSTRAINT chk_connectors_provider_fields CHECK (
        (provider_type = 'composio' AND auth_config_id IS NOT NULL AND url IS NULL) OR
        (provider_type = 'mcp_server' AND (
            (source_kind = 'external_url' AND url IS NOT NULL AND auth_config_id IS NULL) OR
            (source_kind = 'uploaded_build' AND auth_config_id IS NULL AND (
                (build_status IN ('pending', 'building', 'failed')) OR
                (build_status = 'running' AND url IS NOT NULL)
            ))
        )) OR
        (provider_type = 'system' AND url IS NOT NULL AND auth_type = 'none')
    );

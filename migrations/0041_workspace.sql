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

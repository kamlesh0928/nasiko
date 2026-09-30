//! Connect OpenCode to the Nasiko LLM router with an isolated runtime plugin.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::api::Client;
use crate::commands::coding_agent_router::{self, AgentSpec, ConnectionBinding};
use crate::config;

const ROUTER_VERSION: u32 = 1;
const ROUTER_PLUGIN: &str = "nasiko-llm-router.js";
const ROUTER_MARKER: &str = "nasiko-router-version:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConnectionState {
    #[serde(flatten)]
    binding: ConnectionBinding,
    plugin_path: PathBuf,
    plugin_version: u32,
    /// Whether the generated plugin embeds an MCP gateway credential. `false` for connections
    /// made before this field existed, and for a control plane with no public gateway URL.
    #[serde(default)]
    mcp_installed: bool,
}

pub fn connect(agent: Option<&str>, llm_config: Option<&str>) -> Result<()> {
    let _opencode = which::which("opencode")
        .context("OpenCode is not installed or 'opencode' is not on PATH")?;
    let nasiko = std::env::current_exe().context("cannot locate the nasiko executable")?;
    let plugin_path = config_path().join("plugins").join(ROUTER_PLUGIN);
    if let Some(previous) = load_state()?
        && previous.plugin_path != plugin_path
    {
        bail!(
            "OpenCode routing is connected through {}; run `nasiko disconnect opencode` before reconnecting with a different config directory",
            previous.plugin_path.display()
        );
    }
    if plugin_path.exists() {
        let body = fs::read(&plugin_path)
            .with_context(|| format!("failed to read {}", plugin_path.display()))?;
        require_managed_plugin(&plugin_path, &body)?;
    }
    let prepared = coding_agent_router::prepare(
        AgentSpec {
            id: "opencode",
            display_name: "OpenCode",
            default_name: "opencode",
        },
        agent,
        llm_config,
        nasiko.clone(),
    )?;
    // Minting is a network call layered onto an otherwise local-file install; a failure here
    // (or an older control plane with no gateway configured) only softens to a status line —
    // OpenCode routing must still connect. The credential is folded into the same generated
    // plugin `install_artifacts` already writes, so a write failure is already the existing
    // full-rollback path below — it also needs to revoke the freshly minted credential, since
    // nothing was left registered to use it.
    let (mcp_credential, mcp_line) = mint_mcp_credential(&prepared);
    let state = ConnectionState {
        binding: prepared.binding.clone(),
        plugin_path: plugin_path.clone(),
        plugin_version: ROUTER_VERSION,
        mcp_installed: mcp_credential.is_some(),
    };
    let body = plugin_body(&nasiko, &state.binding.cluster_url, mcp_credential.as_ref());
    if let Err(error) = install_artifacts(&state_path(), &plugin_path, &state, body.as_bytes()) {
        if mcp_credential.is_some() {
            let client = Client::from_cluster_entry_with_timeout(
                &prepared.entry,
                Some(std::time::Duration::from_secs(10)),
            );
            let _ = coding_agent_router::revoke_mcp_credential(&client, &prepared.binding.agent_id);
        }
        return match coding_agent_router::rollback_config(&prepared) {
            Ok(()) => Err(error),
            Err(rollback) => Err(error.context(format!(
                "local install failed and the prior Nasiko LLM config could not be restored: {rollback:#}"
            ))),
        };
    }

    let provider = prepared
        .resolved_config
        .get("provider")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("router");
    let model = prepared
        .resolved_config
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("policy-selected");
    println!(
        "Connected OpenCode to Nasiko ({}, {provider}/{model}).",
        state.binding.cluster
    );
    println!("Routing:          nasiko/router");
    println!("Installed plugin: {}", plugin_path.display());
    println!("{mcp_line}");
    println!("Restart OpenCode so it loads the new router plugin.");
    println!("Session reporting is separate: nasiko agents install opencode");
    Ok(())
}

/// Mints the MCP gateway credential for this connection. Returns the status line the caller
/// prints alongside the LLM-routing success message; `Some` means the caller must fold the
/// credential into the plugin template it is about to generate.
fn mint_mcp_credential(
    prepared: &coding_agent_router::PreparedConnection,
) -> (Option<coding_agent_router::McpCredential>, String) {
    let client = Client::from_cluster_entry_with_timeout(
        &prepared.entry,
        Some(std::time::Duration::from_secs(10)),
    );
    match coding_agent_router::mcp_credential(&client, &prepared.binding.agent_id) {
        Ok(Some(credential)) => {
            let line = format!(
                "MCP gateway: connected (server \"{}\")",
                coding_agent_router::MCP_SERVER_NAME
            );
            (Some(credential), line)
        }
        Ok(None) => (
            None,
            "MCP gateway: not configured on this control plane (MCP_GATEWAY_PUBLIC_URL unset); skipping"
                .to_string(),
        ),
        Err(error) => (
            None,
            format!(
                "MCP gateway: unavailable ({error:#}); LLM routing is connected, MCP tools are not"
            ),
        ),
    }
}

pub fn disconnect(force: bool) -> Result<()> {
    let Some(state) = load_state()? else {
        println!("OpenCode routing is not connected to Nasiko.");
        return Ok(());
    };
    coding_agent_router::disconnect_preflight("OpenCode", &["opencode"], force)?;
    if state.mcp_installed {
        revoke_mcp_credential_best_effort(&state.binding);
    }
    remove_managed_plugin_or_preserve(&state.plugin_path)?;
    let path = state_path();
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("failed to remove {}", path.display()))?;
    }
    println!("Disconnected OpenCode routing from Nasiko.");
    println!("Session reporting, queued telemetry, history, and the registered agent were kept.");
    println!("Restart OpenCode so it unloads the router plugin.");
    Ok(())
}

pub fn status() -> Result<()> {
    let Some(state) = load_state()? else {
        println!("OpenCode routing:          not connected");
        println!(
            "OpenCode session reporting: {}",
            crate::commands::integration::reporting_status_for("opencode")?
        );
        println!("Connect routing with: nasiko connect opencode");
        return Ok(());
    };
    println!("OpenCode routing:          connected");
    println!(
        "Cluster:                   {} ({})",
        state.binding.cluster, state.binding.cluster_url
    );
    println!("Agent:                     {}", state.binding.agent_name);
    println!(
        "Nasiko auth:               {}",
        coding_agent_router::auth_status(&state.binding)?
    );
    println!("Router plugin:             {}", plugin_status(&state));
    println!("Provider/model:            nasiko/router");
    println!(
        "OpenCode session reporting: {}",
        crate::commands::integration::reporting_status_for("opencode")?
    );
    Ok(())
}

/// Hidden helper called by the generated plugin. Stdout is credential JSON only.
pub fn credential() -> Result<()> {
    let state = load_state()?.ok_or_else(|| {
        anyhow::anyhow!("OpenCode routing is not connected; run: nasiko connect opencode")
    })?;
    let credential = coding_agent_router::credential(&state.binding)?;
    println!("{}", serde_json::to_string(&credential)?);
    Ok(())
}

pub fn config_path() -> PathBuf {
    config_path_from(
        std::env::var_os("OPENCODE_CONFIG_DIR"),
        std::env::var_os("XDG_CONFIG_HOME"),
        dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")),
    )
}

fn config_path_from(config_dir: Option<OsString>, xdg: Option<OsString>, home: PathBuf) -> PathBuf {
    if let Some(path) = config_dir.filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    xdg.filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"))
        .join("opencode")
}

fn state_path() -> PathBuf {
    coding_agent_router::state_path("opencode-router")
}

fn load_state() -> Result<Option<ConnectionState>> {
    let state: Option<ConnectionState> = coding_agent_router::read_json(&state_path())?;
    if let Some(state) = &state
        && state.binding.version != coding_agent_router::STATE_VERSION
    {
        bail!(
            "unsupported OpenCode connection state version {}",
            state.binding.version
        );
    }
    Ok(state)
}

fn install_artifacts(
    state_path: &Path,
    plugin_path: &Path,
    state: &ConnectionState,
    plugin: &[u8],
) -> Result<()> {
    let old_state = fs::read(state_path).ok();
    let old_plugin = fs::read(plugin_path).ok();
    if let Some(body) = old_plugin.as_deref() {
        require_managed_plugin(plugin_path, body)?;
    }
    coding_agent_router::atomic_write(plugin_path, plugin)?;
    if let Err(error) = coding_agent_router::atomic_write_json(state_path, state) {
        restore_file(plugin_path, old_plugin.as_deref());
        restore_file(state_path, old_state.as_deref());
        return Err(error.context("failed to save OpenCode routing state; plugin rolled back"));
    }

    if let Ok(Some(previous)) = old_state
        .as_deref()
        .map(serde_json::from_slice::<ConnectionState>)
        .transpose()
        && previous.plugin_path != plugin_path
    {
        restore_file(plugin_path, old_plugin.as_deref());
        restore_file(state_path, old_state.as_deref());
        bail!(
            "refusing to reconnect across OpenCode config directories; disconnect {} first",
            previous.plugin_path.display()
        );
    }
    Ok(())
}

fn restore_file(path: &Path, content: Option<&[u8]>) {
    match content {
        Some(content) => {
            let _ = coding_agent_router::atomic_write(path, content);
        }
        None => {
            let _ = fs::remove_file(path);
        }
    }
}

/// Best-effort server-side revoke during disconnect: resolves the bound cluster from config and
/// warns rather than fails, since disconnect must still remove the local plugin even when the
/// control plane is unreachable.
fn revoke_mcp_credential_best_effort(binding: &ConnectionBinding) {
    let result = (|| -> Result<()> {
        let cfg = config::load()?;
        let entry = cfg.clusters.get(&binding.cluster).ok_or_else(|| {
            anyhow::anyhow!("Nasiko cluster '{}' no longer exists", binding.cluster)
        })?;
        let client = Client::from_cluster_entry_with_timeout(
            entry,
            Some(std::time::Duration::from_secs(10)),
        );
        coding_agent_router::revoke_mcp_credential(&client, &binding.agent_id)
    })();
    if let Err(error) = result {
        eprintln!("warning: failed to revoke the MCP gateway credential: {error:#}");
    }
}

#[cfg(test)]
fn remove_managed_plugin(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let body = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    require_managed_plugin(path, &body)?;
    fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))
}

fn remove_managed_plugin_or_preserve(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let body = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    if let Err(error) = require_managed_plugin(path, &body) {
        eprintln!("warning: {error}; leaving it unchanged");
        return Ok(());
    }
    fs::remove_file(path).with_context(|| format!("failed to remove {}", path.display()))
}

fn require_managed_plugin(path: &Path, body: &[u8]) -> Result<u32> {
    let body = std::str::from_utf8(body)
        .with_context(|| format!("{} is not a text plugin", path.display()))?;
    let version = router_version(body).ok_or_else(|| {
        anyhow::anyhow!(
            "refusing to overwrite or remove unrecognized OpenCode plugin {}",
            path.display()
        )
    })?;
    if version == 0 || version > ROUTER_VERSION {
        bail!(
            "refusing to overwrite or remove OpenCode router plugin version {version} at {}",
            path.display()
        );
    }
    Ok(version)
}

fn router_version(body: &str) -> Option<u32> {
    let first = body.lines().next()?;
    if !body.contains("export const NasikoLlmRouter") {
        return None;
    }
    first
        .strip_prefix("// Managed by nasiko - do not edit. ")?
        .strip_prefix(ROUTER_MARKER)?
        .trim()
        .parse()
        .ok()
}

fn plugin_status(state: &ConnectionState) -> String {
    let Ok(body) = fs::read_to_string(&state.plugin_path) else {
        return "missing".into();
    };
    match router_version(&body) {
        Some(version) if version == state.plugin_version && version == ROUTER_VERSION => {
            format!("active (v{version})")
        }
        Some(version) => format!("stale or changed (v{version})"),
        None => "changed since connect".into(),
    }
}

fn plugin_body(
    executable: &Path,
    cluster_url: &str,
    mcp_credential: Option<&coding_agent_router::McpCredential>,
) -> String {
    let executable =
        serde_json::to_string(&executable.to_string_lossy()).expect("serializable path");
    let base_url = serde_json::to_string(&format!("{}/v1", cluster_url.trim_end_matches('/')))
        .expect("serializable URL");
    let mcp_constants = match mcp_credential {
        Some(credential) => {
            let url = credential
                .gateway_url
                .as_deref()
                .expect("plugin_body is only called with a minted gateway_url");
            format!(
                "const MCP_URL = {}\nconst MCP_TOKEN = {}\n",
                serde_json::to_string(url).expect("serializable URL"),
                serde_json::to_string(&credential.token).expect("serializable token"),
            )
        }
        None => String::new(),
    };
    // Emitted only when a credential was minted, so an unconfigured/unreachable control plane
    // produces a plugin identical to one from before MCP registration existed.
    let mcp_config_block = if mcp_credential.is_some() {
        r#"      config.mcp ??= {}
      config.mcp["nasiko"] = {
        type: "remote",
        url: MCP_URL,
        headers: { Authorization: `Bearer ${MCP_TOKEN}` },
        enabled: true,
      }
"#
    } else {
        ""
    };
    format!(
        r#"// Managed by nasiko - do not edit. nasiko-router-version: {ROUTER_VERSION}
const NASIKO = {executable}
const BASE_URL = {base_url}
const REFRESH_SKEW_MS = 60_000
{mcp_constants}
export const NasikoLlmRouter = async () => {{
  let cached
  let refreshPromise

  const refresh = async () => {{
    const process = Bun.spawn([NASIKO, "__coding-agent-token", "opencode"], {{
      stdout: "pipe",
      stderr: "pipe",
    }})
    const outputPromise = new Response(process.stdout).text()
    const errorPromise = new Response(process.stderr).text()
    const timeout = Symbol("timeout")
    const status = await Promise.race([
      process.exited,
      Bun.sleep(10_000).then(() => timeout),
    ])
    if (status === timeout) {{
      process.kill()
      await process.exited.catch(() => undefined)
    }}
    const [output] = await Promise.all([outputPromise, errorPromise])
    if (status === timeout) throw new Error("Nasiko credential helper timed out; run `nasiko status opencode`")
    if (status !== 0) throw new Error("Nasiko credential helper failed; run `nasiko status opencode`")
    let credential
    try {{
      credential = JSON.parse(output)
    }} catch {{
      throw new Error("Nasiko credential helper returned an invalid response")
    }}
    const expires = Date.parse(credential.expires_at)
    if (!credential.token || !Number.isFinite(expires) || expires <= Date.now() + REFRESH_SKEW_MS) {{
      throw new Error("Nasiko credential helper returned an incomplete response")
    }}
    cached = {{ token: credential.token, expires }}
    return cached
  }}

  const credential = async () => {{
    if (cached && cached.expires - REFRESH_SKEW_MS > Date.now()) return cached
    if (!refreshPromise) refreshPromise = refresh().finally(() => {{ refreshPromise = undefined }})
    return refreshPromise
  }}

  const routedFetch = async (input, init = {{}}) => {{
    for (let attempt = 0; attempt < 2; attempt++) {{
      const current = await credential()
      const headers = new Headers(init.headers)
      headers.set("Authorization", `Bearer ${{current.token}}`)
      const response = await fetch(input, {{ ...init, headers }})
      if (response.status !== 401 || attempt === 1) return response
      cached = undefined
    }}
    throw new Error("Nasiko authentication retry exhausted")
  }}

  return {{
    config: async (config) => {{
      config.provider ??= {{}}
      config.provider.nasiko = {{
        npm: "@ai-sdk/openai-compatible",
        name: "Nasiko Router",
        options: {{ baseURL: BASE_URL, apiKey: "nasiko-managed", fetch: routedFetch }},
        models: {{ router: {{ name: "Nasiko Router", tool_call: true }} }},
      }}
      config.model = "nasiko/router"
      config.small_model = "nasiko/router"
{mcp_config_block}    }},
  }}
}}
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ConnectionBinding {
        ConnectionBinding {
            version: 1,
            integration_id: Some("opencode".into()),
            cluster: "local".into(),
            cluster_url: "https://nasiko.example/".into(),
            principal_id: Some("owner".into()),
            agent_id: "agent".into(),
            agent_name: "opencode-owner".into(),
            executable: Some(PathBuf::from("/tmp/nasiko")),
        }
    }

    #[test]
    fn state_lacking_the_mcp_field_still_deserializes() {
        let state: ConnectionState = serde_json::from_value(serde_json::json!({
            "version": 1,
            "cluster": "local",
            "cluster_url": "https://nasiko.example/",
            "agent_id": "agent",
            "agent_name": "opencode-owner",
            "plugin_path": "/tmp/plugins/nasiko-llm-router.js",
            "plugin_version": 1
        }))
        .unwrap();
        assert!(!state.mcp_installed);
    }

    #[test]
    fn config_path_precedence_is_deterministic() {
        assert_eq!(
            config_path_from(
                Some("/custom".into()),
                Some("/xdg".into()),
                "/home/me".into()
            ),
            PathBuf::from("/custom")
        );
        assert_eq!(
            config_path_from(None, Some("/xdg".into()), "/home/me".into()),
            PathBuf::from("/xdg/opencode")
        );
        assert_eq!(
            config_path_from(None, None, "/home/me".into()),
            PathBuf::from("/home/me/.config/opencode")
        );
    }

    #[test]
    fn generated_plugin_has_dynamic_fail_closed_auth_semantics() {
        let body = plugin_body(
            Path::new("/Applications/Nasiko CLI/nasiko"),
            "https://cp/",
            None,
        );
        assert!(body.contains("nasiko-router-version: 1"));
        assert!(body.contains("@ai-sdk/openai-compatible"));
        assert!(body.contains("https://cp/v1"));
        assert!(body.contains("config.model = \"nasiko/router\""));
        assert!(body.contains("config.small_model = \"nasiko/router\""));
        assert!(body.contains("Bun.spawn([NASIKO, \"__coding-agent-token\", \"opencode\"]"));
        assert!(body.contains("REFRESH_SKEW_MS"));
        assert!(body.contains("Bun.sleep(10_000)"));
        assert!(body.contains("process.kill()"));
        assert!(body.contains("new Response(process.stderr).text()"));
        assert!(body.contains("expires <= Date.now() + REFRESH_SKEW_MS"));
        assert!(body.contains("if (!refreshPromise)"));
        assert!(body.contains("for (let attempt = 0; attempt < 2; attempt++)"));
        assert!(body.contains("response.status !== 401 || attempt === 1"));
        assert!(body.contains("headers.set(\"Authorization\", `Bearer ${current.token}`)"));
        assert!(!body.contains("enabled_providers"));
    }

    fn mcp_credential() -> coding_agent_router::McpCredential {
        coding_agent_router::McpCredential {
            token: "ngt_secret".into(),
            gateway_url: Some("https://cp.example/api/mcp".into()),
            connect_url: Some("https://cp.example/api/mcp/s/ngt_secret".into()),
        }
    }

    #[test]
    fn no_credential_means_no_mcp_block_is_emitted() {
        let body = plugin_body(Path::new("/nasiko"), "https://cp/", None);
        assert!(!body.contains("config.mcp"));
        assert!(!body.contains("MCP_URL"));
        assert!(!body.contains("MCP_TOKEN"));
    }

    #[test]
    fn a_minted_credential_emits_the_mcp_block_with_the_exact_url_and_token() {
        let credential = mcp_credential();
        let body = plugin_body(Path::new("/nasiko"), "https://cp/", Some(&credential));
        assert!(body.contains(r#"const MCP_URL = "https://cp.example/api/mcp""#));
        assert!(body.contains(r#"const MCP_TOKEN = "ngt_secret""#));
        assert!(body.contains(r#"config.mcp["nasiko"] = {"#));
        assert!(body.contains(r#"type: "remote""#));
        assert!(body.contains("url: MCP_URL"));
        assert!(body.contains("headers: { Authorization: `Bearer ${MCP_TOKEN}` }"));
        assert!(body.contains("enabled: true"));
    }

    #[test]
    fn generated_plugin_is_valid_javascript_when_node_is_available() {
        let Ok(node) = which::which("node") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin.js");
        fs::write(&path, plugin_body(Path::new("/nasiko"), "https://cp", None)).unwrap();
        let status = std::process::Command::new(node)
            .arg("--check")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn generated_plugin_with_an_mcp_block_is_valid_javascript_when_node_is_available() {
        let Ok(node) = which::which("node") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plugin.js");
        let credential = mcp_credential();
        fs::write(
            &path,
            plugin_body(Path::new("/nasiko"), "https://cp", Some(&credential)),
        )
        .unwrap();
        let status = std::process::Command::new(node)
            .arg("--check")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn marker_safety_preserves_user_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ROUTER_PLUGIN);
        fs::write(&path, "export const UserPlugin = true\n").unwrap();
        assert!(remove_managed_plugin(&path).is_err());
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            "export const UserPlugin = true\n"
        );
    }

    #[test]
    fn marker_text_outside_the_exact_signature_is_not_managed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ROUTER_PLUGIN);
        fs::write(
            &path,
            "// user plugin mentioning nasiko-router-version: 1\nexport const NasikoLlmRouter = true\n",
        )
        .unwrap();
        assert!(remove_managed_plugin(&path).is_err());
        assert!(path.exists());
    }

    #[test]
    fn disconnect_style_removal_preserves_user_replacement_without_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ROUTER_PLUGIN);
        fs::write(&path, "export const UserReplacement = true\n").unwrap();
        remove_managed_plugin_or_preserve(&path).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn disconnect_artifact_removal_preserves_reporting_plugin_and_jsonc() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("opencode.jsonc");
        let reporting = dir.path().join("plugins/nasiko-session-report.js");
        let router = dir.path().join("plugins").join(ROUTER_PLUGIN);
        fs::create_dir_all(router.parent().unwrap()).unwrap();
        fs::write(&config, "{ // keep comments\n}\n").unwrap();
        fs::write(&reporting, "reporting bytes\n").unwrap();
        fs::write(
            &router,
            plugin_body(Path::new("/nasiko"), "https://cp", None),
        )
        .unwrap();
        remove_managed_plugin(&router).unwrap();
        assert!(!router.exists());
        assert_eq!(
            fs::read_to_string(config).unwrap(),
            "{ // keep comments\n}\n"
        );
        assert_eq!(fs::read_to_string(reporting).unwrap(), "reporting bytes\n");
    }

    #[test]
    fn failed_state_write_rolls_back_new_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let plugin = dir.path().join("plugins").join(ROUTER_PLUGIN);
        let invalid_state = dir.path().join("state-directory");
        fs::create_dir(&invalid_state).unwrap();
        let state = ConnectionState {
            binding: binding(),
            plugin_path: plugin.clone(),
            plugin_version: ROUTER_VERSION,
            mcp_installed: false,
        };
        assert!(
            install_artifacts(
                &invalid_state,
                &plugin,
                &state,
                plugin_body(Path::new("/n"), "https://c", None).as_bytes()
            )
            .is_err()
        );
        assert!(!plugin.exists());
    }
}

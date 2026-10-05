//! One command sets up a local coding agent end to end.
//!
//! `nasiko agents install <agent>` connects LLM routing and the MCP gateway (for the clients
//! that support them) and then installs session reporting; `nasiko agents uninstall <agent>`
//! reverses both. Routing goes first because it is the step that can be rolled back cleanly
//! by its own client module; reporting is installed only once routing is settled, so a
//! reporting failure never leaves routing half-done.

use anyhow::{Context, Result, bail};

use super::agents::Agent;
use super::state::IntegrationState;
use super::{InstallOptions, install, resolve, uninstall};
use crate::commands::{claude, codex, opencode};

/// Options accepted by `nasiko agents install`.
pub struct SetupOptions<'a> {
    pub agent_id: &'a str,
    /// Keep prompt and response text out of exported spans.
    pub no_content: bool,
    /// Existing routing agent name or UUID; defaults to this account's own row.
    pub routing_agent: Option<&'a str>,
    /// Nasiko LLM config name or UUID; defaults to the agent's current config.
    pub llm_config: Option<&'a str>,
}

/// One unit of work in a setup or teardown plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    ConnectRouting,
    SkipRoutingAlreadyConnected,
    RoutingUnsupported,
    InstallReporting,
    UninstallReporting,
    DisconnectRouting,
}

/// Set up routing, the MCP gateway and session reporting for one coding agent.
pub fn setup(options: SetupOptions<'_>) -> Result<()> {
    let agent = resolve(options.agent_id)?;
    let spec = agent.spec();
    let routing = RoutingClient::for_agent(agent);
    let routing_flags_given = options.routing_agent.is_some() || options.llm_config.is_some();
    if routing.is_none() && routing_flags_given {
        bail!(
            "--agent and --config apply only to agents with LLM routing ({}); {} supports session reporting only",
            routing_ids(),
            spec.display_name
        );
    }

    let plan = plan_setup(agent, routing.is_some_and(RoutingClient::is_connected));
    let routing_ready = !plan.contains(&Step::RoutingUnsupported);
    for step in plan {
        match step {
            Step::ConnectRouting => routing
                .expect("plan connects routing only for agents that support it")
                .connect(options.routing_agent, options.llm_config)?,
            Step::SkipRoutingAlreadyConnected => {
                println!(
                    "{}: routing and MCP gateway already connected; keeping them",
                    spec.display_name
                );
                if routing_flags_given {
                    eprintln!(
                        "warning: --agent/--config ignored; to change routing run `nasiko disconnect {}` first",
                        spec.id
                    );
                }
            }
            Step::RoutingUnsupported => println!(
                "{}: LLM routing and the MCP gateway are not supported for it; installing session reporting only",
                spec.display_name
            ),
            Step::InstallReporting => {
                let result = install(InstallOptions {
                    agent_id: spec.id,
                    no_content: options.no_content,
                });
                if routing_ready {
                    result.with_context(|| {
                        format!(
                            "routing and the MCP gateway are connected for {} but session reporting failed; rerun: nasiko agents install {}",
                            spec.display_name, spec.id
                        )
                    })?;
                } else {
                    result?;
                }
            }
            Step::UninstallReporting | Step::DisconnectRouting => {
                unreachable!("plan_setup yields setup steps only")
            }
        }
    }
    Ok(())
}

/// Remove session reporting and disconnect routing + MCP for one coding agent.
///
/// Best-effort: every applicable step runs even if an earlier one failed, and the failures are
/// reported together so a rerun has nothing left to guess about.
pub fn teardown(agent_id: &str, force: bool) -> Result<()> {
    let agent = resolve(agent_id)?;
    let spec = agent.spec();
    let routing = RoutingClient::for_agent(agent);
    let reporting_installed =
        IntegrationState::load()?.get(spec.id).is_some() || agent.installed_version().is_some();
    let plan = plan_teardown(
        reporting_installed,
        routing.is_some_and(RoutingClient::is_connected),
        routing.is_some(),
    );
    if plan.is_empty() {
        println!("{}: nothing to remove", spec.display_name);
        return Ok(());
    }

    let mut failures = Vec::new();
    for step in plan {
        let (label, result) = match step {
            Step::UninstallReporting => ("session reporting", uninstall(spec.id)),
            Step::DisconnectRouting => (
                "routing and MCP gateway",
                routing
                    .expect("plan disconnects routing only for agents that support it")
                    .disconnect(force),
            ),
            Step::ConnectRouting
            | Step::SkipRoutingAlreadyConnected
            | Step::RoutingUnsupported
            | Step::InstallReporting => unreachable!("plan_teardown yields teardown steps only"),
        };
        if let Err(error) = result {
            failures.push(format!("{label}: {error:#}"));
        }
    }
    if failures.is_empty() {
        return Ok(());
    }
    bail!(
        "{} teardown incomplete — {}",
        spec.display_name,
        failures.join("; ")
    )
}

/// The steps `setup` runs, in order. Routing is settled first; reporting always follows.
pub(crate) fn plan_setup(agent: Agent, already_connected: bool) -> Vec<Step> {
    let routing = match (RoutingClient::for_agent(agent), already_connected) {
        (None, _) => Step::RoutingUnsupported,
        (Some(_), true) => Step::SkipRoutingAlreadyConnected,
        (Some(_), false) => Step::ConnectRouting,
    };
    vec![routing, Step::InstallReporting]
}

/// The steps `teardown` runs, in order: reporting first, then routing. Empty when nothing is
/// installed.
pub(crate) fn plan_teardown(
    reporting_installed: bool,
    routing_connected: bool,
    routing_supported: bool,
) -> Vec<Step> {
    let mut steps = Vec::new();
    if reporting_installed {
        steps.push(Step::UninstallReporting);
    }
    if routing_supported && routing_connected {
        steps.push(Step::DisconnectRouting);
    }
    steps
}

/// The client modules that own LLM routing and MCP gateway state. Cursor has none: its CLI
/// talks to a proprietary backend rather than a provider API, so only reporting applies.
#[derive(Debug, Clone, Copy)]
enum RoutingClient {
    Claude,
    Codex,
    OpenCode,
}

impl RoutingClient {
    fn for_agent(agent: Agent) -> Option<Self> {
        match agent {
            Agent::Claude => Some(Self::Claude),
            Agent::Codex => Some(Self::Codex),
            Agent::OpenCode => Some(Self::OpenCode),
            Agent::Cursor => None,
        }
    }

    fn is_connected(self) -> bool {
        match self {
            Self::Claude => claude::is_connected(),
            Self::Codex => codex::is_connected(),
            Self::OpenCode => opencode::is_connected(),
        }
    }

    fn connect(self, routing_agent: Option<&str>, llm_config: Option<&str>) -> Result<()> {
        match self {
            Self::Claude => claude::connect(routing_agent, llm_config),
            Self::Codex => codex::connect(routing_agent, llm_config),
            Self::OpenCode => opencode::connect(routing_agent, llm_config),
        }
    }

    fn disconnect(self, force: bool) -> Result<()> {
        match self {
            Self::Claude => claude::disconnect(force),
            Self::Codex => codex::disconnect(force),
            Self::OpenCode => opencode::disconnect(force),
        }
    }
}

fn routing_ids() -> String {
    Agent::ALL
        .iter()
        .copied()
        .filter(|agent| RoutingClient::for_agent(*agent).is_some())
        .map(|agent| agent.spec().id)
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTING_AGENTS: [Agent; 3] = [Agent::Claude, Agent::Codex, Agent::OpenCode];

    #[test]
    fn setup_connects_routing_then_installs_reporting_for_routing_agents() {
        for agent in ROUTING_AGENTS {
            assert_eq!(
                plan_setup(agent, false),
                vec![Step::ConnectRouting, Step::InstallReporting],
                "{agent:?}"
            );
        }
    }

    #[test]
    fn setup_keeps_an_existing_routing_connection_and_still_installs_reporting() {
        for agent in ROUTING_AGENTS {
            assert_eq!(
                plan_setup(agent, true),
                vec![Step::SkipRoutingAlreadyConnected, Step::InstallReporting],
                "{agent:?}"
            );
        }
    }

    #[test]
    fn setup_installs_reporting_only_for_cursor_whatever_the_connection_flag_says() {
        for already_connected in [false, true] {
            assert_eq!(
                plan_setup(Agent::Cursor, already_connected),
                vec![Step::RoutingUnsupported, Step::InstallReporting]
            );
        }
    }

    #[test]
    fn every_setup_plan_ends_with_reporting_and_has_exactly_one_routing_step() {
        for agent in Agent::ALL.iter().copied() {
            for already_connected in [false, true] {
                let plan = plan_setup(agent, already_connected);
                assert_eq!(plan.len(), 2, "{agent:?}");
                assert_eq!(plan[1], Step::InstallReporting, "{agent:?}");
                assert!(
                    !matches!(
                        plan[0],
                        Step::InstallReporting | Step::UninstallReporting | Step::DisconnectRouting
                    ),
                    "{agent:?}"
                );
            }
        }
    }

    #[test]
    fn teardown_removes_reporting_before_routing() {
        assert_eq!(
            plan_teardown(true, true, true),
            vec![Step::UninstallReporting, Step::DisconnectRouting]
        );
    }

    #[test]
    fn teardown_plans_only_what_is_installed() {
        assert_eq!(
            plan_teardown(true, false, true),
            vec![Step::UninstallReporting]
        );
        assert_eq!(
            plan_teardown(false, true, true),
            vec![Step::DisconnectRouting]
        );
        assert!(plan_teardown(false, false, true).is_empty());
    }

    #[test]
    fn teardown_never_disconnects_routing_for_an_agent_without_it() {
        for (reporting_installed, routing_connected) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let plan = plan_teardown(reporting_installed, routing_connected, false);
            assert!(!plan.contains(&Step::DisconnectRouting));
            assert_eq!(
                plan.contains(&Step::UninstallReporting),
                reporting_installed
            );
        }
    }

    #[test]
    fn only_cursor_lacks_a_routing_client() {
        for agent in Agent::ALL.iter().copied() {
            assert_eq!(
                RoutingClient::for_agent(agent).is_none(),
                agent == Agent::Cursor,
                "{agent:?}"
            );
        }
        assert_eq!(routing_ids(), "claude, codex, opencode");
    }
}

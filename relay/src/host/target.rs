//! What a project is: where the AI lives, and where the gateway runs (#234).
//!
//! Only `Devcontainer` on Docker Desktop is implemented. The others are named here so that every
//! place that depends on the answer asks this type instead of assuming, and refuses what it does
//! not know how to do (design/sgw-host.md, "対象").

use std::fmt;

/// The Docker that runs the gateway, and the values that depend on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    DockerDesktop,
    Colima,
    /// Docker Engine on a Linux host
    Engine,
}

/// Where the relay is when the AI lives in a Docker Sandbox: in a Docker on the host, or as a
/// host process (Docker Sandboxes need neither Docker Desktop nor Docker Engine).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayHost {
    Docker(Runtime),
    HostProcess,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The AI lives in a dev container on the gateway's bridge
    Devcontainer { gateway: Runtime },
    /// The AI lives in a Docker Sandbox (its own microVM) and reaches the relay through
    /// `host.docker.internal`
    Sbx { gateway: RelayHost },
}

impl Target {
    /// The one target this version implements.
    pub const DEFAULT: Target = Target::Devcontainer {
        gateway: Runtime::DockerDesktop,
    };

    /// Whether the AI's traffic crosses the gateway's bridge, where DNS, the firewall and the
    /// host-side FORWARD rules apply. A sandbox's does not: only the relay's published ports
    /// reach it.
    pub fn agent_on_bridge(&self) -> bool {
        matches!(self, Target::Devcontainer { .. })
    }

    /// Whether this version of `sgw` knows how to set the target up.
    pub fn supported(&self) -> bool {
        *self == Target::DEFAULT
    }

    /// `devcontainer`, `devcontainer/colima`, `sbx`, `sbx/host` … as `init --target` takes it.
    pub fn parse(s: &str) -> Result<Target, String> {
        let (env, rt) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        match (env, rt) {
            ("devcontainer", None | Some("docker-desktop")) => Ok(Target::Devcontainer {
                gateway: Runtime::DockerDesktop,
            }),
            ("devcontainer", Some("colima")) => Ok(Target::Devcontainer {
                gateway: Runtime::Colima,
            }),
            ("devcontainer", Some("engine")) => Ok(Target::Devcontainer {
                gateway: Runtime::Engine,
            }),
            ("sbx", None | Some("docker-desktop")) => Ok(Target::Sbx {
                gateway: RelayHost::Docker(Runtime::DockerDesktop),
            }),
            ("sbx", Some("colima")) => Ok(Target::Sbx {
                gateway: RelayHost::Docker(Runtime::Colima),
            }),
            ("sbx", Some("engine")) => Ok(Target::Sbx {
                gateway: RelayHost::Docker(Runtime::Engine),
            }),
            ("sbx", Some("host")) => Ok(Target::Sbx {
                gateway: RelayHost::HostProcess,
            }),
            _ => Err(format!(
                "unknown target '{s}'; one of devcontainer[/docker-desktop|/colima|/engine], sbx[/docker-desktop|/colima|/engine|/host]"
            )),
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rt = |r: &Runtime| match r {
            Runtime::DockerDesktop => "docker-desktop",
            Runtime::Colima => "colima",
            Runtime::Engine => "engine",
        };
        match self {
            Target::Devcontainer { gateway } => write!(f, "devcontainer/{}", rt(gateway)),
            Target::Sbx {
                gateway: RelayHost::Docker(r),
            } => write!(f, "sbx/{}", rt(r)),
            Target::Sbx {
                gateway: RelayHost::HostProcess,
            } => write!(f, "sbx/host"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_the_only_supported_target() {
        assert!(Target::DEFAULT.supported());
        assert!(!Target::parse("devcontainer/colima").unwrap().supported());
        assert!(!Target::parse("sbx").unwrap().supported());
        assert!(!Target::parse("sbx/host").unwrap().supported());
    }

    #[test]
    fn a_sandbox_is_not_on_the_bridge() {
        assert!(Target::DEFAULT.agent_on_bridge());
        assert!(!Target::parse("sbx/colima").unwrap().agent_on_bridge());
    }

    #[test]
    fn spellings_round_trip() {
        for s in [
            "devcontainer/docker-desktop",
            "devcontainer/colima",
            "devcontainer/engine",
            "sbx/docker-desktop",
            "sbx/colima",
            "sbx/engine",
            "sbx/host",
        ] {
            assert_eq!(Target::parse(s).unwrap().to_string(), s);
        }
        assert_eq!(Target::parse("devcontainer").unwrap(), Target::DEFAULT);
        assert!(Target::parse("vm").is_err());
        assert!(
            Target::parse("devcontainer/host").is_err(),
            "a dev container needs a Docker"
        );
    }
}

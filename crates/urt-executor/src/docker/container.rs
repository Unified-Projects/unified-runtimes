//! Container configuration and info types

use std::collections::HashMap;

/// Configuration for creating a container
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    pub name: String,
    pub image: String,
    pub hostname: String,
    pub entrypoint: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub env: HashMap<String, String>,
    pub cpus: f64,
    pub memory: u64, // bytes
    pub network: Option<String>,
    pub restart_policy: String,
    pub labels: HashMap<String, String>,
    pub mounts: Vec<Mount>,
}

/// A volume mount
#[derive(Debug, Clone)]
pub struct Mount {
    pub source: String,
    pub target: String,
    pub read_only: bool,
}

impl ContainerConfig {
    pub fn new(name: &str, image: &str) -> Self {
        Self {
            name: name.to_string(),
            image: image.to_string(),
            hostname: String::new(),
            entrypoint: None,
            cmd: None,
            env: HashMap::new(),
            cpus: 1.0,
            memory: 512 * 1024 * 1024, // 512MB default
            network: None,
            restart_policy: "no".to_string(),
            labels: HashMap::new(),
            mounts: Vec::new(),
        }
    }

    pub fn with_hostname(mut self, hostname: &str) -> Self {
        self.hostname = hostname.to_string();
        self
    }

    #[allow(dead_code)]
    pub fn with_entrypoint(mut self, entrypoint: Vec<String>) -> Self {
        self.entrypoint = Some(entrypoint);
        self
    }

    pub fn with_cmd(mut self, cmd: Vec<String>) -> Self {
        self.cmd = Some(cmd);
        self
    }

    #[allow(dead_code)]
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_envs(mut self, envs: HashMap<String, String>) -> Self {
        self.env.extend(envs);
        self
    }

    pub fn with_cpus(mut self, cpus: f64) -> Self {
        self.cpus = cpus;
        self
    }

    pub fn with_memory_mb(mut self, mb: u64) -> Self {
        self.memory = mb * 1024 * 1024;
        self
    }

    pub fn with_network(mut self, network: &str) -> Self {
        self.network = Some(network.to_string());
        self
    }

    pub fn with_restart_policy(mut self, policy: &str) -> Self {
        self.restart_policy = policy.to_string();
        self
    }

    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.insert(key.to_string(), value.to_string());
        self
    }

    pub fn with_mount(mut self, source: &str, target: &str, read_only: bool) -> Self {
        self.mounts.push(Mount {
            source: source.to_string(),
            target: target.to_string(),
            read_only,
        });
        self
    }

    /// Convert env HashMap to Docker format (KEY=VALUE)
    pub fn env_vec(&self) -> Vec<String> {
        self.env
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect()
    }
}

/// Information about a running container
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ContainerInfo {
    pub id: String,
    pub name: String,
    pub image: String,
    /// Canonical Docker state (e.g. running, exited, paused)
    pub state: String,
    /// Human-readable Docker status (e.g. Up 5 seconds)
    pub status: String,
    pub created: i64,
    /// Container labels (empty on list endpoints when unavailable)
    pub labels: HashMap<String, String>,
    /// Container environment variables keyed by variable name
    pub env: HashMap<String, String>,
    /// Container hostname (internal)
    pub hostname: String,
    /// Exit code of the last run (None while running or when not reported)
    pub exit_code: Option<i64>,
    /// Whether the kernel OOM killer stopped the container
    pub oom_killed: bool,
    /// Docker restart policy name (empty on list endpoints)
    pub restart_policy: String,
    /// Maximum retries for an `on-failure` policy; 0 means unlimited
    pub restart_max_retries: i64,
    /// Number of times Docker has restarted the container
    pub restart_count: i64,
}

impl ContainerInfo {
    /// Whether Docker's own restart policy will bring this container back
    /// after the exit it currently reports.
    pub fn docker_will_restart(&self) -> bool {
        if self.state.eq_ignore_ascii_case("restarting") {
            return true;
        }
        match self.restart_policy.as_str() {
            "always" | "unless-stopped" => true,
            "on-failure" => {
                self.exit_code.unwrap_or(0) != 0
                    && (self.restart_max_retries <= 0
                        || self.restart_count < self.restart_max_retries)
            }
            _ => false,
        }
    }
}

/// Parsed form of a `restartPolicy` request value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartPolicySpec {
    No,
    Always,
    UnlessStopped,
    /// `on-failure` with an optional retry cap; `None` retries without limit.
    OnFailure(Option<u32>),
}

impl RestartPolicySpec {
    /// Parse the Docker CLI spelling: `no`, `always`, `unless-stopped`,
    /// `on-failure`, `on-failure:<n>`. Anything else is treated as `no`.
    pub fn parse(value: &str) -> Self {
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            "always" => Self::Always,
            "unless-stopped" => Self::UnlessStopped,
            "on-failure" => Self::OnFailure(None),
            other => match other.strip_prefix("on-failure:") {
                Some(count) => match count.trim().parse::<u32>() {
                    Ok(0) => Self::OnFailure(None),
                    Ok(n) => Self::OnFailure(Some(n)),
                    Err(_) => Self::No,
                },
                None => Self::No,
            },
        }
    }
}

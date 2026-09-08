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
}

/// Whether a container belongs to the executor running under `hostname`.
///
/// Several executors can share one Docker daemon, so `urt.managed=true` and
/// `urt.runtime_id` are not on their own enough to decide that a container is
/// ours to stop or remove. The `urt.executor_hostname` label is authoritative;
/// the name prefix is the fallback for containers created before that label
/// existed.
pub fn belongs_to_executor(container: &ContainerInfo, hostname: &str) -> bool {
    if let Some(executor_hostname) = container
        .labels
        .get("urt.executor_hostname")
        .filter(|value| !value.is_empty())
    {
        return executor_hostname == hostname;
    }

    container
        .name
        .strip_prefix(&format!("{}-", hostname))
        .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(name: &str, labels: &[(&str, &str)]) -> ContainerInfo {
        ContainerInfo {
            id: "abc".to_string(),
            name: name.to_string(),
            image: "openruntimes/node:v5-22".to_string(),
            state: "running".to_string(),
            status: "Up 3 seconds".to_string(),
            created: 0,
            labels: labels
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            env: HashMap::new(),
            hostname: String::new(),
        }
    }

    #[test]
    fn the_executor_hostname_label_decides_ownership() {
        let owned = container("exc2-fn-1", &[("urt.executor_hostname", "exc1")]);
        assert!(belongs_to_executor(&owned, "exc1"));
        assert!(!belongs_to_executor(&owned, "exc2"));
    }

    #[test]
    fn an_unlabelled_container_falls_back_to_its_name_prefix() {
        let legacy = container("exc1-fn-1", &[]);
        assert!(belongs_to_executor(&legacy, "exc1"));
        assert!(!belongs_to_executor(&legacy, "exc2"));
    }

    #[test]
    fn a_blank_label_does_not_claim_another_executors_runtime() {
        let blank = container("exc1-fn-1", &[("urt.executor_hostname", "")]);
        assert!(belongs_to_executor(&blank, "exc1"));
        assert!(!belongs_to_executor(&blank, "exc2"));
    }
}

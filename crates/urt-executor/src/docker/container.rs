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
    pub status: String,
    pub created: i64,
}

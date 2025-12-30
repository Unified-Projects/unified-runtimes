use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    // Server Configuration
    pub host: String,
    pub port: u16,
    pub secret: Option<String>,

    // Runtime Configuration
    pub runtime_entrypoint: String,
    pub runtime_port: u16,
    pub runtime_host: String,

    // Lifecycle Configuration
    pub idle_timeout: u64, // Seconds before stopping inactive runtime (0 = disable)
    pub cold_start: bool,  // If true, wait for first request to start. If false, start on boot.
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            host: env::var("URT_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("URT_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3000),
            secret: env::var("URT_SECRET").ok(),

            runtime_entrypoint: env::var("URT_ENTRYPOINT")
                .unwrap_or_else(|_| "index.js".to_string()),
            runtime_port: env::var("URT_RUNTIME_PORT")
                .ok()
                .and_then(|p| p.parse().ok())
                .unwrap_or(3001),
            runtime_host: "127.0.0.1".to_string(),

            idle_timeout: env::var("URT_IDLE_TIMEOUT")
                .ok()
                .and_then(|t| t.parse().ok())
                .unwrap_or(0), // Default: Never stop
            cold_start: env::var("URT_COLD_START")
                .map(|v| v.to_lowercase() == "true")
                .unwrap_or(true), // Default: Lazy load
        }
    }
}

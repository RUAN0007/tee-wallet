use serde::Deserialize;
use config::{Config, ConfigError, File};
use trace::TraceConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    pub vsock_port: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SigServerConfig {
    pub grpc: GrpcConfig,
	pub trace: TraceConfig,
}

impl SigServerConfig {
    pub fn load(dir: &str) -> Result<Config, ConfigError> {
        let env = std::env::var("ENV").unwrap_or("default".into());
        Config::builder()
            // .add_source(File::with_name(&format!("{}/default", dir)))
            .add_source(File::with_name(&format!("{}/{}", dir, env)).required(false))
            .add_source(File::with_name(&format!("{}/local", dir)).required(false))
            .add_source(config::Environment::with_prefix("SIG_SERVER"))
            .build()
    }

	pub fn try_new() -> Result<Self, ConfigError> {
        let config = Self::load("config")?;
        config.try_deserialize()
    }
}
use serde::Deserialize;
use config::{Config, ConfigError, File};
use trace::TraceConfig;
use once_cell::sync::Lazy;
use std::sync::RwLock;
use trace::{init_tracing, WorkerGuard};

#[derive(Debug, Clone, Deserialize)]
pub struct DexConfig {
	pub api_key : String,
	pub secret_key : String,
	pub passphrase : String,
	pub project_id : String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitOrderConfig {
	pub dex : DexConfig,
	pub trace : TraceConfig,
}

// static LimitOrderConfig : config;

impl LimitOrderConfig {
    pub fn load(dir: &str) -> Result<Config, ConfigError> {
        let env = std::env::var("ENV").unwrap_or("default".into());
        Config::builder()
            // .add_source(File::with_name(&format!("{}/default", dir)))
            .add_source(File::with_name(&format!("{}/{}", dir, env)).required(false))
            .add_source(File::with_name(&format!("{}/local", dir)).required(false))
            .add_source(config::Environment::with_prefix("LIMIT_ORDER"))
            .build()
    }

	pub fn try_new() -> Result<Self, ConfigError> {
        let config = Self::load("config")?;
        config.try_deserialize()
    }
}


pub static CONFIG: Lazy<RwLock<LimitOrderConfig>> = Lazy::new(|| {
    RwLock::new(LimitOrderConfig::try_new().expect("Failed to load config"))
});

pub static _GUARDS : RwLock<Vec<WorkerGuard>> = RwLock::new(Vec::new()); // static lifetime to ensure the guards are not dropped

pub fn must_init_with_path(cfg_path: &str) {
    let cfg = LimitOrderConfig::load(&cfg_path)
    .expect(&format!("fail to load config file from {}", cfg_path).to_string());
    let cfg : LimitOrderConfig = cfg.try_deserialize().expect(&format!("fail to deserialize from {}", cfg_path).to_string());

    *_GUARDS.write().unwrap() = init_tracing(cfg.trace.clone());

    *CONFIG.write().unwrap() = cfg;
}

#[cfg(test)]
#[ctor::ctor]
fn init() {
    must_init_with_path("config/"); // load local config from $CARGO_MANIFEST_DIR/config/local.toml
}

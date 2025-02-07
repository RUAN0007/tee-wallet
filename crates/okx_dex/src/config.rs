use serde::Deserialize;
use config::{Config, ConfigError, File};
use once_cell::sync::Lazy;
use std::sync::RwLock;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OkxDexConfig {
	pub api_key : String,
	pub secret_key : String,
	pub passphrase : String,
	pub project_id : String,
}

impl OkxDexConfig {
    pub fn load(dir: &str) -> Result<Config, ConfigError> {
        let env = std::env::var("ENV").unwrap_or("default".into());
        Config::builder()
            // .add_source(File::with_name(&format!("{}/default", dir)))
            .add_source(File::with_name(&format!("{}/{}", dir, env)).required(false))
            .add_source(File::with_name(&format!("{}/local", dir)).required(false))
            .add_source(config::Environment::with_prefix("OKX_DEX"))
            .build()
    }

	pub fn try_new() -> Result<Self, ConfigError> {
        let config = Self::load("config")?;
        config.try_deserialize()
    }
}


pub static CONFIG: Lazy<RwLock<OkxDexConfig>> = Lazy::new(|| {
    RwLock::new(OkxDexConfig::default())
});

pub fn must_init_with_config(cfg: OkxDexConfig) {
    *CONFIG.write().unwrap() = cfg;
}

#[cfg(test)]
pub static _GUARDS : RwLock<Vec<trace::WorkerGuard>> = RwLock::new(Vec::new()); // static lifetime to ensure the guards are not dropped

#[cfg(test)]
#[ctor::ctor]
fn init() {
    let cfg : OkxDexConfig = cfg.try_deserialize().unwrap();
    must_init_with_config(cfg);

    *_GUARDS.write().unwrap() = trace::init_tracing(trace::TraceConfig{
        prefix: "okx_dex".to_string(),
        dir: "logs".to_string(),
        level: tracing::Level::DEBUG,
        console: true,
        flame: false,
    });
}

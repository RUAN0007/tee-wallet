use serde::Deserialize;
use config::{Config, ConfigError, File};
use trace::TraceConfig;

#[derive(Debug, Clone, Deserialize)]
pub struct EnclaveConfig {
    pub grpc: GrpcConfig,
    pub cid : u32,
    pub tcp_proxies: Vec<TcpProxyConfig>,
	pub twitter: TwitterConfig,
    pub okx_dex : okx_dex::config::OkxDexConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TwitterConfig {
	pub bearer_token: String,
	pub polling_interval_sec: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HostConfig {
    pub vsock_proxies: Vec<VsockProxyConfig>,
    pub listen_port : u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcpProxyConfig {
    pub local_tcp_port : u16,
    pub remote_cid : u32,
    pub remote_port : u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct VsockProxyConfig {
    pub local_vsock_port : u32,
    pub remote_host : String,
    pub remote_port : u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GrpcConfig {
    pub vsock_port: u32,
    pub tcp_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScraperConfig {
    pub enclave: EnclaveConfig,
    pub host: HostConfig,
	pub trace: TraceConfig,
}

impl ScraperConfig {
    pub fn load(dir: &str) -> Result<Config, ConfigError> {
        let env = std::env::var("ENV").unwrap_or("default".into());
        Config::builder()
            // .add_source(File::with_name(&format!("{}/default", dir)))
            .add_source(File::with_name(&format!("{}/{}", dir, env)).required(false))
            .add_source(File::with_name(&format!("{}/local", dir)).required(false))
            .add_source(File::with_name(&format!("{}/test", dir)).required(false))
            .add_source(config::Environment::with_prefix("SCRAPER"))
            .build()
    }

	pub fn try_new() -> Result<Self, ConfigError> {
        let config = Self::load("config")?;
        config.try_deserialize()
    }
}

#[cfg(test)]
pub static _GUARDS : RwLock<Vec<WorkerGuard>> = RwLock::new(Vec::new()); // static lifetime to ensure the guards are not dropped

#[cfg(test)]
#[ctor::ctor]
fn init() {
    let cfg = ScraperConfig::load("config/").unwrap();
    let cfg : ScraperConfig = cfg.try_deserialize().unwrap();

    *_GUARDS.write().unwrap() = init_tracing(cfg.trace.clone());
}

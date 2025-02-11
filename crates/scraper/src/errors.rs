use config::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScraperError {
    #[error("config error: {0}")]
    ConfigError(#[from] ConfigError),
    #[error("grpc server error: {0}")]
    ServerError(#[from] tonic::transport::Error),
    #[error("vsock proxy error: {0}")]
    VSockProxyError(String),
    #[error("tcp proxy error: {0}")]
    TcpProxyError(String),
    #[error("listener loop joining error: {0}")]
    ListenerJoinError(#[from] tokio::task::JoinError),
    #[error("invalid config parameter {0}, error: {1}")]
    ConfigParameterError(String, String),
    #[error("twitter error, {0}")]
    TwitterError(#[from] twitter_v2::Error),
    #[error("okx dex error, {0}")]
    OkxDexError(#[from] okx_dex::api::errors::OkxDexError),
}
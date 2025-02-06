use config::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigServerError {
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
}

pub const ERR_EMPTY_ATTESTATION_DOC : &str = "empty attestation document";
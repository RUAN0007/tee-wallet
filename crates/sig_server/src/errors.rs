use config::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigServerError {
    #[error("config error: {0}")]
    ConfigError(#[from] ConfigError),
}
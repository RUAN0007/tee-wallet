use thiserror::Error;

#[derive(Error, Debug)]
pub enum DexError {
    #[error("Network request failed")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Error Response from Remote Host: error code {0}, message: {1}")]
    RemoteError(u32, String),
    
    #[error("Unknown error occurred")]
    Unknown,
}

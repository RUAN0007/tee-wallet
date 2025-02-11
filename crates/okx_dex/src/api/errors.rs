use thiserror::Error;

#[derive(Error, Debug)]
pub enum OkxDexError {
    #[error("Network request failed")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Error Response from Remote Host: error code {0}, message: {1}")]
    RemoteError(String, String),
    
    #[error("Parsing error occurred, {0}")]
    ParseError(String),

    #[error("JSON Parsing error occurred, {0}")]
    JsonParseError(#[from] serde_json::Error),

    #[error("bs58 decoding error occurred, {0}")]
    Bs58DecodingError(#[from] solana_sdk::bs58::decode::Error),

    #[error("other error occurred, {0}")]
    Other(String),
}

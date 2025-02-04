pub mod quote;
pub mod swap;

use thiserror::Error;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::config::CONFIG;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};

pub const HOST : &str = "https://www.okx.com";

pub fn get_headers(method : &str, req_path_with_query_str: &str) -> HeaderMap {
	let current_timestamp = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    tracing::debug!("current_timestamp: {:?}", current_timestamp);
	let msg_to_sign = current_timestamp.clone() + method + req_path_with_query_str;

	let dex_config = CONFIG.read().unwrap().dex.clone();
	let secret_key = dex_config.secret_key;
	let mut mac = Hmac::<Sha256>::new_from_slice(secret_key.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(msg_to_sign.as_bytes());

    // Get the resulting HMAC as bytes
    let result = mac.finalize();
    let sign = base64::encode(result.into_bytes());
    // tracing::debug!("msg_to_sign: {:?}", msg_to_sign);
    // tracing::debug!("secret_key: {:?}", secret_key);
    // tracing::debug!("signiture: {:?}", sign);

    // Example of how to use the signature
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert("OK-ACCESS-KEY", HeaderValue::from_str(&dex_config.api_key).unwrap());
    headers.insert("OK-ACCESS-SIGN", HeaderValue::from_str(&sign).unwrap());
    headers.insert("OK-ACCESS-TIMESTAMP", HeaderValue::from_str(&current_timestamp).unwrap());
    headers.insert("OK-ACCESS-PASSPHRASE", HeaderValue::from_str(&dex_config.passphrase).unwrap());
    headers.insert("OK-ACCESS-PROJECT", HeaderValue::from_str(&dex_config.project_id).unwrap());

    headers
}

#[derive(Error, Debug)]
pub enum DexError {
    #[error("Network request failed")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Error Response from Remote Host: error code {0}, message: {1}")]
    RemoteError(String, String),
    
    #[error("Unknown error occurred")]
    UnmarshalError(#[from] serde_json::Error),

    #[error("Other error: {0}")]
    Other(String),
}

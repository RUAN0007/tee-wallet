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
    
    #[error("Error Response from DEX Remote Host: error code {0}, message: {1}")]
    RemoteError(String, String),
    
    #[error("unmarshal json error: {0}")]
    UnmarshalError(#[from] serde_json::Error),

    #[error("bs58 decode error: {0}")]
    Bs58DecodeError(#[from] solana_sdk::bs58::decode::Error),

    #[error("Other error: {0}")]
    Other(String),
}

#[cfg(test)]
mod tests {
    use solana_client::nonblocking::rpc_client::RpcClient;
    use solana_sdk::transaction::VersionedTransaction;
    use solana_sdk::signature::Signer;
    use solana_sdk::signer::keypair::Keypair;
    use std::fs;
    use std::path::Path;
    use serde_json::Value;
    use bincode;
	use std::env;

    use crate::dex::swap::get_swap_txn_data;

	pub fn must_load_keypair() -> Keypair {
		// Get the path from the environment variable
		let key_path = env::var("SOLANA_KEY_PATH").expect("must set SOLANA_KEY_PATH");
		
		// Read the private key file
		let key_data = fs::read_to_string(Path::new(&key_path)).expect("fail to read from key_path");
		
		// Parse the JSON data
		let json: Value = serde_json::from_str(&key_data).unwrap();
		
		// Convert the JSON array to a Vec<u8>
		let key_bytes: Vec<u8> = json.as_array().unwrap()
			.iter()
			.map(|v| v.as_u64().unwrap() as u8)
			.collect::<Vec<u8>>();
		
		// Create the keypair from the bytes
		Keypair::from_bytes(&key_bytes).unwrap()
	}
    #[ignore = "require local config for API credential and key path"]
    #[tokio::test]
    async fn test_generate_broadcast_tx() {
		let key_pair = must_load_keypair();
		let addr = key_pair.pubkey().to_string();

		let chain_id = 501;
		let amount = 1_000_000; // 0.001 sol
		let from_token_addr = "11111111111111111111111111111111"; // sol
		let to_token_addr = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"; // msol
        let slippage = "0.05";
        // Call the function
        let txn_data = get_swap_txn_data(crate::dex::HOST, chain_id, amount, from_token_addr, to_token_addr, slippage, &addr).await.unwrap();
        let rpc_client = RpcClient::new(std::env::var("SOLANA_RPC_URL").unwrap());

        let txn = bincode::deserialize::<VersionedTransaction>(&txn_data).unwrap();
        let mut msg = txn.message;
        tracing::info!("VersionedMessage: {:?}", msg);

        // Send the versioned transaction
        let recent_blockhash = rpc_client.get_latest_blockhash().await.unwrap();
        msg.set_recent_blockhash(recent_blockhash);
        let signed_txn = VersionedTransaction::try_new(msg, &[&key_pair]).unwrap();  
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        let signature = rpc_client.send_and_confirm_transaction(&signed_txn).await.unwrap();
        tracing::info!("Transaction signature: {:?}", signature);

    }
}
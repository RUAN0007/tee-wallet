use url::Url;
use super::errors::OkxDexError;
use super::get_headers;
use serde::Deserialize;
use solana_sdk::bs58;

const REQ_PATH : &str = "/api/v5/dex/aggregator/swap";


#[derive(Deserialize, Debug)]
struct Response {
    code: String,
    data: Vec<Data>,
    msg: String,
}

#[derive(Deserialize, Debug)]
struct Data {
    tx: Tx,
}

#[derive(Deserialize, Debug)]
struct Tx {
    data: String,
}

fn gen_url(host: &str, chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str, slippage: &str, user_wallet_addr: &str) -> Url {
    let mut url = Url::parse(host).unwrap();
    url.set_path(REQ_PATH);
    url.query_pairs_mut()
        .append_pair("chainId", &chain_id.to_string())
        .append_pair("amount", &amount.to_string())
        .append_pair("fromTokenAddress", from_token_addr)
        .append_pair("toTokenAddress", to_token_addr)
        .append_pair("slippage", slippage)
        .append_pair("userWalletAddress", user_wallet_addr);
    url
}

pub async fn get_swap_txn_data(host: &str, chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str, slippage: &str, user_wallet_addr: &str) -> Result<Vec<u8>, OkxDexError>{
	let url = gen_url(host, chain_id, amount, from_token_addr, to_token_addr, slippage, user_wallet_addr);

    let req_path_with_query_str = url.path().to_string() + "?" + url.query().unwrap();
    let headers = get_headers("GET", &req_path_with_query_str);
    tracing::debug!("req_path_with_query_str: {:?}", req_path_with_query_str);
    let client = reqwest::Client::new();
    let resp = client.get(url.as_str())
        .headers(headers)
        .send()
        .await?;
        

    let body = resp.text().await.map_err(|e| OkxDexError::Other(format!("fail to get response body due to {}", e)))?;
    tracing::debug!("addr: {:?}", user_wallet_addr);
    tracing::debug!("response body: {:?}", body);

    let response: Response = serde_json::from_str(&body)?;
    if response.code != "0" {
        return Err(OkxDexError::RemoteError(response.code, response.msg));
    }
    if response.data.len() == 0 {
        return Err(OkxDexError::Other("No data in response".to_string()));
    }
    let response_data = &response.data[0];
	let decoded_data = bs58::decode(&response_data.tx.data).into_vec()?;
	Ok(decoded_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;
	use crate::api::tests::must_load_keypair;
	use solana_sdk::signature::Signer;

    #[ignore = "require local config for API credential and keyfile path"]
    #[tokio::test]
    async fn test_get_swap_txn_succ() {
		let key_pair = must_load_keypair();
		let addr = key_pair.pubkey().to_string();

		let chain_id = 501;
		let amount = 1_000_000; // 0.001 sol
		let from_token_addr = "11111111111111111111111111111111"; // sol
		let to_token_addr = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"; // wsol
        let slippage = "0.05";
        // Call the function
        let r = get_swap_txn_data(crate::api::HOST, chain_id, amount, from_token_addr, to_token_addr, slippage, &addr).await;
		assert!(r.is_ok());
    }

    #[ignore = "require local config for API credential and keyfile path"]
    #[tokio::test]
    async fn test_get_swap_txn_fail() {
		let key_pair = must_load_keypair();
		let addr = key_pair.pubkey().to_string();
        let slippage = "0.05";

		let invalid_chain_id = 701;
		let amount = 1_000_000; // 0.001 sol
		let from_token_addr = "11111111111111111111111111111111"; // sol
		let to_token_addr = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"; // wsol

        let r = get_swap_txn_data(crate::api::HOST, invalid_chain_id, amount, from_token_addr, to_token_addr, slippage, &addr).await;

        assert!(matches!(r, Err(OkxDexError::RemoteError(code, message)) if code == "51000" && message == "Parameter chainId error"));
    }


    use httpmock::prelude::*;
    #[tokio::test]
    async fn test_get_swap_txn_mock() {
        let server = MockServer::start();

        let chain_id = 501;
		let amount = 1_000_000; // 0.001 sol
		let from_token_addr = "11111111111111111111111111111111"; // sol
		let to_token_addr = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"; // msol
        let user_wallet_addr = "B3ATNguQmHk6MrkCnH85uPzEG9FujtJKmzUUNDT6jNKQ";
        let slippage = "0.05";

        // the real body returned from remote host with request parameters: 
        let server_mock = server.mock(|when, then| {
            when.method(GET)
                .path(REQ_PATH);

            then.status(200)
                .body("{\"code\":\"0\",\"data\":[{\"tx\":{\"data\":\"2c7oHTpLKhQq4ga5MnEBSET2ZKmBe6Fm7r6TEanCmxqFUe3RMWwZu9ugKwpPVqWDDKVPuBSx4ZBitPieb1vgWaXDDyxxZ8D8Yyd1RzworuVUddKNNRiPJeRSsvevCrwmxworoFEeky2RfB2Z25bywpiAAkA8QTfAM4BS2BJDYsgcaMbFRKN8jcYfSTah1qr8Nrwkc1jjk1mVqahEew1kBtY4atUMwMae6zRphYPVvCm56njZVJhASjcvdkUn88po3hnDuUNLWML3tths6GcBAoysz5rzuAgViW2MfWphqiJbRpbMUS3BKFK9gkaWLRVigN8qi3ZuTsSdgRi32tBqNSbD9Cbtb4zTj6GJtjTp3eDTXARH4bqTc5qLKBrQbxHgygW6SzARQPaTSzYkJ3v77KPt1LHeANYbm2E4EP7ZYf5u2CXK2j2waisyvD5xXSFY8t9V14xm1792c8w3tpRoXLpiqGf6HHKwVFnB81rcTCu6AQdnCcyXKnVtJHiXCUHReFMna1Lzz6iWpLc9fUQUSg8f9zgxqZTHq9TzuDLWtzSqDdFBazGzAKZwCBSYPADnRGvefftJejP8MW51tUgh5MVhJJCkHYtDRWPSMemzRPpPsQb42Njnvo6WVsjW9fHtKqYYQ8AJja41fRUbSf6xckPTvShmAuHboa9bX5tUmnHdSNFg6yy2XpVahnTrh5EHSQquVTNx1t5QQCsyoFMV4NKstLiuSo67k4masnDd7mBRnW2LkVjGunvP6LYNZ1o6ctnTyTmba22sFdWGP2gRsqgX7zDJpaz8U6kW2xKSNGJ29FUW4PqByNdWubychXU8m76Dy3TZeiaHXsio3NBkN8hp6M3N8NyEVKqAUS8qGcn3TGLkvrGUEMFswNwhMh3hkpYnxJnMbNhSVrbmyUvc9aoUYc5S7K6Mz8Fki3qiNSmWDEc2mdvJmWw71SJMo5G8ZvzhcqiSW2hL\"}}],\"msg\":\"\"}");
        });
        let host = server.base_url();
        tracing::info!("host: {:?}", host);

        // Call the function
        let r = get_swap_txn_data(&host, chain_id, amount, from_token_addr, to_token_addr, slippage, user_wallet_addr).await;
        server_mock.assert();
		assert!(r.is_ok());
    }
}
use url::Url;
use crate::dex::DexError;
use crate::dex::get_headers;

const REQ_PATH : &str = "/api/v5/dex/aggregator/swap";

fn gen_url(chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str, slippage: &str, user_wallet_addr: &str) -> Url {
    let mut url = Url::parse(crate::dex::HOST).unwrap();
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

pub async fn swap(chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str, slippage: &str, user_wallet_addr: &str) -> Result<Vec<u8>, DexError>{
	let url = gen_url(chain_id, amount, from_token_addr, to_token_addr, slippage, user_wallet_addr);

    let req_path_with_query_str = url.path().to_string() + "?" + url.query().unwrap();
    let headers = get_headers("GET", &req_path_with_query_str);
    tracing::debug!("req_path_with_query_str: {:?}", req_path_with_query_str);
    let client = reqwest::Client::new();
    let resp = client.get(url.as_str())
        .headers(headers)
        .send()
        .await?;
        

    let body = resp.text().await.unwrap();

	return Err(DexError::Other("".to_string()))
}
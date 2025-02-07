use super::get_headers;
use super::errors::OkxDexError;
use serde::Deserialize;
use url::Url;

const REQ_PATH : &str = "/api/v5/dex/aggregator/quote";

#[derive(Deserialize, Debug)]
struct Response {
    code: String,
    data: Vec<Data>,
    msg: String,
}

#[derive(Deserialize, Debug)]
struct Data {
    #[serde(rename = "toToken")]
    to_token: Token,
    #[serde(rename = "toTokenAmount")]
    to_token_amount: String,
}

#[derive(Deserialize, Debug)]
struct Token {
    decimal: String,
}

pub struct TokenAmount {
    pub amount : u64,
    pub decimal : u8,
}

fn gen_url(host: &str, chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str) -> Url {
    let mut url = Url::parse(host).unwrap();
    url.set_path(REQ_PATH);
    url.query_pairs_mut()
        .append_pair("chainId", &chain_id.to_string())
        .append_pair("amount", &amount.to_string())
        .append_pair("fromTokenAddress", from_token_addr)
        .append_pair("toTokenAddress", to_token_addr);
    url
}

pub async fn get_quote(host: &str, chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str) -> Result<TokenAmount, OkxDexError>{
	let url = gen_url(host, chain_id, amount, from_token_addr, to_token_addr);
    let req_path_with_query_str = url.path().to_string() + "?" + url.query().unwrap();
    let headers = get_headers("GET", &req_path_with_query_str);
    tracing::debug!("req_path_with_query_str: {:?}", req_path_with_query_str);
    let client = reqwest::Client::new();
    let resp = client.get(url.as_str())
        .headers(headers)
        .send()
        .await?;
        

    let body = resp.text().await.map_err(|e| OkxDexError::ParseError(format!("fail to parse response body due to {}", e)))?;

    tracing::debug!("response_data: {:?}", body);

    let response: Response = serde_json::from_str(&body)?;
    if response.code != "0" {
        return Err(OkxDexError::RemoteError(response.code, response.msg));
    }
    if response.data.len() == 0 {
        return Err(OkxDexError::ParseError("No data in response".to_string()));
    }
    let response_data = &response.data[0];
    let out_amount =  response_data.to_token_amount.parse::<u64>().map_err(|e| OkxDexError::ParseError(format!("fail to parse to_token_amount due to {}", e)))?;
    let decimal =  response_data.to_token.decimal.parse::<u8>().map_err(|e| OkxDexError::ParseError(format!("fail to parse to_token.decimal due to {}", e)))?;

    return Ok(TokenAmount {
        amount: out_amount,
        decimal: decimal,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[ignore = "require local config for API credential"]
    #[tokio::test]
    async fn test_get_quote_succ() {
		let chain_id = 501;
		let amount = 1_000_000; // 0.001 sol
		let from_token_addr = "11111111111111111111111111111111"; // sol
		let to_token_addr = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"; // msol
        // Call the function
        let r = get_quote(crate::dex::HOST, chain_id, amount, from_token_addr, to_token_addr).await.unwrap();
        assert_eq!(r.amount, 1_000_000);
        assert_eq!(r.decimal, 9);
    }

    #[ignore = "require local config for API credential"]
    #[tokio::test]
    async fn test_get_quote_fail() {
		let invalid_chain_id = 50001; // invalid chainID
		let amount = 1_000_000; // 0.001 sol
		let from_token_addr = "11111111111111111111111111111111"; // sol
		let to_token_addr = "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So"; // msol
        // Call the function
        let r = get_quote(crate::dex::HOST, invalid_chain_id, amount, from_token_addr, to_token_addr).await;
        assert!(matches!(r, Err(OkxDexError::RemoteError(code, message)) if code == "51000" && message == "Parameter chainId error"));
    }
}
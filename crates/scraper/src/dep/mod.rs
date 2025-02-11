use tokio::sync::RwLock;
use crate::errors::ScraperError;
use once_cell::sync::Lazy;

pub mod twitter_cli {
	use super::*;
	use time::OffsetDateTime;
	use twitter_v2::TwitterApi;
	use twitter_v2::authorization::BearerToken;
	use twitter_v2::id::NumericId;
	use twitter_v2::Tweet;

	pub struct TwitterCli {
		cli: TwitterApi<BearerToken>,
	}

	pub async fn init(bearer_token : String) -> Result<(), ScraperError> {
		let cli = TwitterCli::new(bearer_token);
		*TWITTER_CLI.write().await = cli;
		Ok(())
	}

	impl TwitterCli {
		pub fn new(bearer_token : String) -> Self {
			let auth = BearerToken::new(bearer_token);
			let cli = TwitterApi::new(auth);
			Self{cli}
		}

		pub async fn get_user_id(&self, username: &str) -> Result<NumericId, ScraperError> {
			let user = self.cli.get_user_by_username(username).send().await?;
			let user = user.into_data().ok_or(twitter_v2::Error::Custom("No Data".to_string()))?;
			Ok(user.id)
		}

		pub async fn get_user_tweets_since(&self, user_id: NumericId, dt : OffsetDateTime) -> Result<Vec<Tweet>, ScraperError> {
			let tweets = self.cli.get_user_tweets(user_id).start_time(dt).send().await?;
			let tweets = tweets.into_data().ok_or(twitter_v2::Error::Custom("No Data".to_string()))?;
			Ok(tweets)
		}
	}

	pub static TWITTER_CLI : Lazy<RwLock<TwitterCli>> = Lazy::new(|| RwLock::new(TwitterCli::new("".to_owned())));
}

pub mod okx_dex_cli {
	use super::*;
	use okx_dex::config::OkxDexConfig;

	#[derive(Default)]
	pub struct OkxDexCli {
		endpoint : String,
	}

	pub async fn init(endpoint : &str, config : &OkxDexConfig) -> Result<(), ScraperError> {
		okx_dex::config::must_init_with_config(config.clone());
		*OKX_DEX_CLI.write().await = OkxDexCli::new(endpoint.to_string());
		Ok(())
	}

	impl OkxDexCli {
		
		pub fn new(endpoint : String) -> Self {
			Self{endpoint}
		}

		pub async fn get_swap_txn_data(&self, chain_id: u32, amount: u64, from_token_addr: &str, to_token_addr: &str, slippage: &str, user_wallet_addr: &str) -> Result<Vec<u8>, ScraperError>{
			let txn_data  = okx_dex::api::swap::get_swap_txn_data(&self.endpoint, chain_id, amount, from_token_addr, to_token_addr, slippage, user_wallet_addr).await?;
			Ok(txn_data)
		}
	}

	pub static OKX_DEX_CLI : Lazy<RwLock<OkxDexCli>> = Lazy::new(|| RwLock::new(OkxDexCli::default()));
}
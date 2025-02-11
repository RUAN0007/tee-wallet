use std::time::Duration;
use crate::errors::ScraperError;
use crate::core::scraping_registry::SCRAPING_REGISTRY;
use crate::dep::{okx_dex_cli, twitter_cli};
use solana_sdk::message::VersionedMessage;
use solana_sdk::transaction::VersionedTransaction;
use solana_client::nonblocking::rpc_client::RpcClient;

pub struct ScrapingRunner{
	last_scraped: Option<time::OffsetDateTime>,
	solana_cli : RpcClient,
}

#[derive(Debug)]
pub struct SwapArgs {
	chain_id : u32,
	from_token_addr : String,
	to_token_addr : String,
	from_amount : u64,
	slippage : String,
	addr : String,
}

fn parse_swap_arg_from_tweet(tweet_text : &str) -> Option<SwapArgs> {
	// TODO: 
	None
}

impl ScrapingRunner {
	pub fn new(solana_end_point : &str) -> Self {
		Self {
			last_scraped: None,
			solana_cli: RpcClient::new(solana_end_point.to_string())
		}
	}

	async fn sign(&self, versioned_msg_and_wallet_addr : Vec<(VersionedMessage, String)>) -> Vec<(VersionedTransaction, String)> {
		let mut signed_txn_and_wallet_addr : Vec<(VersionedTransaction, String)> = vec![];

        let recent_blockhash = self.solana_cli.get_latest_blockhash().await.unwrap();
		for (mut msg, wallet_addr) in versioned_msg_and_wallet_addr {
        	msg.set_recent_blockhash(recent_blockhash);
			// TODO: invoke signing service
		}

		signed_txn_and_wallet_addr.into_iter().filter(|(txn, wallet_addr)| {
			if let Err(e)  = txn.verify_and_hash_message() {
				tracing::error!("txn {:?} for wallet {:?} is invalid due to error {:?}", txn, wallet_addr, e);
				return false
			}
			true
		}).collect()
	}

	async fn broadcast(&self, signed_txn_and_wallet_addrs : Vec<(VersionedTransaction, String)>) {
		// TODO: broadcast txns concurently
		for (signed_txn, wallet_addr) in signed_txn_and_wallet_addrs {
			let broadcast_result = self.solana_cli.send_transaction(&signed_txn).await;
			if let Err(e) = broadcast_result {
				tracing::error!("Fail to broadcast txn {:?} for wallet addr {:?} due to error {:?}", signed_txn, wallet_addr, e);
				continue;
			}
			let signature = broadcast_result.unwrap();

			tracing::info!("succesfully broadcast txn {:?} for wallet addr {:?}, with ID {:?}", signed_txn, wallet_addr, signature);
		}
	}

	async fn scrape(&mut self) {

		let scraped_targets = {
			let r = SCRAPING_REGISTRY.read().await;
			r.get_scraped_targets().await
		};
		let since = self.last_scraped.unwrap_or(time::OffsetDateTime::now_utc());
		let mut versioned_msg_and_wallet_addr = vec![];
		for (twitter_user_id, req_ids) in scraped_targets {
			let user_tweets = twitter_cli::TWITTER_CLI.read().await.get_user_tweets_since(twitter_user_id, since).await;
			if let Err(err) = user_tweets {
				tracing::error!("Fail to get user tweets for user {:?} since {:?} due to error {:?}", twitter_user_id, since, err);
				continue;
			}
			let tweets = user_tweets.unwrap();
			let mut wallet_addrs = vec![];
			for req_id in req_ids {
				// TODO: request concurrently. 
				let req = SCRAPING_REGISTRY.read().await.get_original_req(req_id).await;
				if req.is_none() {
					tracing::error!("Fail to get original req for req_id {:?}", req_id);
					continue;
				}
				let req = req.unwrap();
				wallet_addrs.push(req.wallet_addr);
			}
			tracing::info!("get {:?} tweets from user {:?} since {:?}, scraping for {:?} wallets", tweets.len(), twitter_user_id, since, wallet_addrs.len());


			for tweet in tweets {
				let swap_args = parse_swap_arg_from_tweet(&tweet.text);
				if swap_args.is_none() {
					continue;
				}
				let swap_args = swap_args.unwrap();
				tracing::info!("get swap args {:?} from tweet text: {:?}, ", swap_args, tweet.text);

				for wallet_addr in &wallet_addrs {
					let swap_result = okx_dex_cli::OKX_DEX_CLI.read().await.get_swap_txn_data(swap_args.chain_id, swap_args.from_amount, &swap_args.from_token_addr, &swap_args.to_token_addr, &swap_args.slippage, &wallet_addr).await;
					if let Err(err) = swap_result {
						tracing::error!("Fail to get swap txn data for wallet {:?} with params {:?} due to error {:?}", wallet_addr, swap_args, err);
						continue;
					}
					let txn_data = swap_result.unwrap();
        			let txn = bincode::deserialize::<VersionedTransaction>(&txn_data);
					if let Err(e) = txn {
						tracing::error!("Fail to deserialize txn data for wallet {:?} with params {:?} due to error {:?}", wallet_addr, swap_args, e);
						continue
					}
					let txn = txn.unwrap();
					versioned_msg_and_wallet_addr.push((txn.message, wallet_addr.clone()));
				}
			}

		}
		let signed_txns = self.sign(versioned_msg_and_wallet_addr).await;
		self.broadcast(signed_txns).await;
	}

	pub async fn run(&mut self, interval : Duration) {
		tracing::info!("start to run scraping runner");

		let mut interval = tokio::time::interval(Duration::from_secs(10));
		loop {
			interval.tick().await;
			tracing::info!("prepare to scrap on {:?}", time::OffsetDateTime::now_utc());
			self.scrape().await;
			self.last_scraped = Some(time::OffsetDateTime::now_utc());
		}
	}
}

use std::hash::{Hash, Hasher};
use std::hash::DefaultHasher;
use tokio::sync::RwLock;
use std::collections::HashMap;

use crate::errors::ScraperError;
use crate::service::scraper_svc::{ScrapeTwitterReq, TwitterScrapingRecord};
use twitter_v2::id::NumericId as TwitterUserID;
use once_cell::sync::Lazy;

type ScrapeTwitterReqID = u64;

impl ScrapeTwitterReq {
	pub fn id(&self) -> ScrapeTwitterReqID {
		let mut hasher = DefaultHasher::new();
		self.hash(&mut hasher);
		hasher.finish()
	}
}

pub struct ScrapingRegistry {
	user_scraping_reqs: HashMap<String, Vec<ScrapeTwitterReqID>>, 
	requests: HashMap<ScrapeTwitterReqID, ScrapeTwitterReq>,
	scraped_targets: HashMap<TwitterUserID, Vec<ScrapeTwitterReqID>>, // twitter_user_address -> [req_id]
	scraping_records : HashMap<ScrapeTwitterReqID, Vec<TwitterScrapingRecord>>
}

pub static SCRAPING_REGISTRY : Lazy<RwLock<ScrapingRegistry>> = Lazy::new(|| RwLock::new(ScrapingRegistry::new()));

impl ScrapingRegistry {
	pub fn new() -> Self {
		Self {
			user_scraping_reqs: HashMap::new(),
			requests: HashMap::new(),
			scraped_targets: HashMap::new(),
			scraping_records: HashMap::new()
		}
	}

	pub async fn get_original_req(&self, req_id: ScrapeTwitterReqID) -> Option<ScrapeTwitterReq> {
		self.requests.get(&req_id).map(|v| v.clone())
	}

	pub async fn get_scraping_records_for_req_id(&self, req_id: ScrapeTwitterReqID) -> Option<Vec<TwitterScrapingRecord>> {
		self.scraping_records.get(&req_id).map(|v| v.clone())
	}

	pub async fn add_scraping_record(&mut self, req_id: ScrapeTwitterReqID, record: TwitterScrapingRecord) -> Result<(), ScraperError>{
		self.scraping_records.entry(req_id).or_insert(Vec::new()).push(record);
		Ok(())
	}

	pub async fn add_twitter_scraping_req(&mut self, user_addr : &str, req: ScrapeTwitterReq) -> Result<u64, ScraperError> {
		let username = req.username.clone();
		let twitter_user_id = crate::dep::twitter_cli::TWITTER_CLI.read().await.get_user_id(&username).await?;

		let req_id = req.id();
		self.requests.insert(req_id, req);
		self.user_scraping_reqs.entry(user_addr.to_string()).or_insert(Vec::new()).push(req_id);
		self.scraped_targets.entry(twitter_user_id).or_insert(Vec::new()).push(req_id);

		Ok(req_id)
	}

	pub async fn get_scraped_targets(&self) -> HashMap<TwitterUserID, Vec<ScrapeTwitterReqID>> {
		self.scraped_targets.clone()
	}
}
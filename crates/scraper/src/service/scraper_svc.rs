use tonic::{Request, Response, Status};
use scraper_server::Scraper;
use crate::enclave;
use crate::errors;

tonic::include_proto!("scraper");

#[derive(Debug, Default)]
pub struct ScraperHandler {}

#[tonic::async_trait]
impl Scraper for ScraperHandler {
    async fn scrape_twitter(
        &self,
        request: Request<ScrapeTwitterReq>,
    ) -> Result<Response<ScrapeTwitterResp>, Status> {
		  Err(Status::unimplemented("ScrapeTwitter not implemented"))
    }

    async fn get_twitter_scraping_records(
        &self,
        request: Request<GetTwitterScrapingRecordsReq>,
    ) -> Result<Response<GetTwitterScrapingRecordsResp>, Status> {
      Err(Status::unimplemented("GetTwitterScrapingRecords not implemented"))
    }
}
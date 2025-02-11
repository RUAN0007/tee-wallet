use tonic::{Request, Response, Status};
use scraper_server::Scraper;
use crate::core::scraping_registry::SCRAPING_REGISTRY;

tonic::include_proto!("scraper");

#[derive(Debug, Default)]
pub struct ScraperHandler {}

#[tonic::async_trait]
impl Scraper for ScraperHandler {
    async fn scrape_twitter(
        &self,
        mut request: Request<ScrapeTwitterReq>,
    ) -> Result<Response<ScrapeTwitterResp>, Status> {

        utils::middleware::validate_body_hash(&request)?;

        // verifiy user pub key
        let addr = utils::middleware::addr_from_header(&request)?;
        if request.get_ref().wallet_addr.is_empty() {
            request.get_mut().wallet_addr = addr.clone();
        }

        let id = SCRAPING_REGISTRY.write().await.add_twitter_scraping_req(&addr, request.into_inner()).await.map_err(|e| Status::internal(format!("Fail to add twitter scraping req due to error {:?}", e)))?;
        Ok(Response::new(ScrapeTwitterResp{id}))
    }

    async fn get_twitter_scraping_records(
        &self,
        request: Request<GetTwitterScrapingRecordsReq>,
    ) -> Result<Response<GetTwitterScrapingRecordsResp>, Status> {

        utils::middleware::validate_body_hash(&request)?;

        let req_id = request.get_ref().original_req_id;
        let r = SCRAPING_REGISTRY.read().await;
        let original_req = r.get_original_req(req_id).await.ok_or(Status::not_found("No original request found"))?;
        let records = r.get_scraping_records_for_req_id(req_id).await.ok_or(Status::not_found("No records found"))?;

        let resp = GetTwitterScrapingRecordsResp{
            original_req: Some(original_req),
            records: records,
        };

        Ok(Response::new(resp))
    }
}
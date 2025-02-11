fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute("scraper.ScrapeTwitterReq", "#[derive(Hash)]")
        .type_attribute("scraper.TwitterScrapingRecord", "#[derive(Hash)]")
        .compile_protos(&["proto/scraper.proto"], &["proto/"])?;
    Ok(())
}
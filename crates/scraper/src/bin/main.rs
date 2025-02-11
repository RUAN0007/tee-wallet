use clap::{Parser, Subcommand};
use std::result::Result;
use scraper::{
    errors::ScraperError,
    config::ScraperConfig,
    enclave,
    host,
};
use trace::{init_tracing, WorkerGuard};
use tonic::async_trait;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: ScraperCommand,
}

#[async_trait]
pub trait Execute {
    async fn execute(&self) -> Result<(), ScraperError>;
}

#[derive(Subcommand)]
pub enum ScraperCommand {
    Enclave {
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },

    Host {
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },
}

// setup the tracing and load the config
async fn setup(cfg_path : &String) -> Result<(Vec<WorkerGuard>, ScraperConfig), ScraperError> {
    let cfg = ScraperConfig::load(&cfg_path)
        .map_err(|e| ScraperError::ConfigError(e))?;
    let cfg : ScraperConfig = cfg.try_deserialize().unwrap();
    let g = init_tracing(cfg.trace.clone());
    scraper::dep::twitter_cli::init(cfg.enclave.twitter.bearer_token.clone()).await?;
    scraper::dep::okx_dex_cli::init(okx_dex::api::HOST, &cfg.enclave.okx_dex).await?;

    tracing::info!(
        "prepare to launch with config: {:?}",
        cfg
    );
    return Ok((g, cfg));
}

#[async_trait]
impl Execute for ScraperCommand {
    async fn execute(&self) -> Result<(), ScraperError> {
        match self {
            ScraperCommand::Enclave { cfg_path } => {
                let (_g, config) = setup(cfg_path).await?;
                enclave::start(config).await?;
                return Ok(());
            }

            ScraperCommand::Host { cfg_path } => {
                let (_g, config) = setup(cfg_path).await?;
                host::start(config).await?;
                return Ok(());
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let _r = cli.command.execute().await;
}
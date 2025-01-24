use clap::{Parser, Subcommand};
use std::result::Result;
use sig_server::{
    errors::SigServerError,
    config::SigServerConfig,
    enclave,
    host,
};
use trace::{init_tracing, WorkerGuard};
use tonic::async_trait;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: SigServerCommand,
}

#[async_trait]
pub trait Execute {
    async fn execute(&self) -> Result<(), SigServerError>;
}

#[derive(Subcommand)]
pub enum SigServerCommand {
    Enclave {
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },

    Host {
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },

    #[cfg(debug_assertions)]
    Echo { // To test the host can receive enclave traffic from the vsock
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },
}

// setup the tracing and load the config
fn setup (cfg_path : &String) -> Result<(Vec<WorkerGuard>, SigServerConfig), SigServerError> {
    let cfg = SigServerConfig::load(&cfg_path)
        .map_err(|e| SigServerError::ConfigError(e))?;
    let cfg : SigServerConfig = cfg.try_deserialize().unwrap();
    let g = init_tracing(cfg.trace.clone());

    tracing::info!(
        "prepare to launch with config: {:?}",
        cfg
    );
    return Ok((g, cfg));
}

#[async_trait]
impl Execute for SigServerCommand {
    async fn execute(&self) -> Result<(), SigServerError> {
        match self {
            SigServerCommand::Enclave { cfg_path } => {
                let (_g, config) = setup(cfg_path)?;
                enclave::start(config).await?;
                return Ok(());
            }

            SigServerCommand::Host { cfg_path } => {
                let (_g, config) = setup(cfg_path)?;
                host::start(config).await?;
                return Ok(());
            }

            #[cfg(debug_assertions)]
            SigServerCommand::Echo {cfg_path} => {
                let (_g, config) = setup(cfg_path)?;
                host::echo(config).await?; 
                return Ok(());
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let r = cli.command.execute().await;
    println!("sig server result: {:?}", r);
}
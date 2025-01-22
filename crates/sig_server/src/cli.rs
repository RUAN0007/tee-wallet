use clap::{Parser, Subcommand};
use std::result::Result;
use crate::{
    errors::SigServerError,
    config::SigServerConfig,
};
use trace::init_tracing;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: SigServerCommand,
}

pub trait Execute {
    fn execute(&self) -> Result<(), SigServerError>;
}

#[derive(Subcommand)]
pub enum SigServerCommand {
    Run {
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },
}

impl Execute for SigServerCommand {
    fn execute(&self) -> Result<(), SigServerError> {
        match self {
            SigServerCommand::Run { cfg_path } => {
                let cfg = SigServerConfig::load(&cfg_path)
                    .map_err(|e| SigServerError::ConfigError(e))?;
                let cfg : SigServerConfig = cfg.try_deserialize().unwrap();

                let _g = init_tracing(cfg.trace.clone());
                tracing::info!(
                    "start with config: {:?}",
                    cfg
                );
                return Ok(());
            }
        }
    }
}


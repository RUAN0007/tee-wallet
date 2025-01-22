use sig_server::cli::{Cli, Execute};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    let r = cli.command.execute();
    println!("sig server result: {:?}", r);
}
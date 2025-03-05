use tonic::async_trait;
use clap::{Parser, Subcommand};
use std::result::Result;
use trace::{init_tracing, WorkerGuard};
use proxy::config::ProxyConfig;

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: ProxyCmd,
}

#[async_trait]
pub trait Execute {
    async fn execute(&self) -> Result<(), String>;
}

#[derive(Subcommand)]
pub enum ProxyCmd {
    Run {
        #[arg(short, long)]
        cfg_path: String, // path to config file
    },
}

fn setup(cfg_path : &String) -> (Vec<WorkerGuard>, ProxyConfig) {
    let cfg = ProxyConfig::load(&cfg_path).unwrap();
    let cfg : ProxyConfig = cfg.try_deserialize().unwrap();
    let g = init_tracing(cfg.trace.clone());

    tracing::info!(
        "prepare to launch with config: {:?}",
        cfg
    );
    return (g, cfg);
}

#[async_trait]
impl Execute for ProxyCmd {
    async fn execute(&self) -> Result<(), String> {
        match self {
            ProxyCmd::Run { cfg_path } => {
                let (_g, config) = setup(cfg_path);
				run(config).await;
                return Ok(());
            }
        }
    }
}
#[cfg(not(target_os = "linux"))]
async fn run(_config: ProxyConfig) {
	println!("loaded config: {:?}", _config);
	panic!("Only support linux");
}

#[cfg(target_os = "linux")]
async fn run(config: ProxyConfig) {
	let mut proxies: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();

    for tcp_proxy_config in config.tcp_proxies.iter() {
        let local_port = tcp_proxy_config.local_tcp_port;
        let remote_cid = tcp_proxy_config.remote_cid;
        let remote_port = tcp_proxy_config.remote_port;

        let tcp_proxy = proxy::tcp::TcpProxy::new(local_port, remote_cid, remote_port).unwrap();
        let tcp_proxy = std::sync::Arc::new(tcp_proxy);

        let listener = tcp_proxy.listen().await.unwrap();
        tracing::info!("Starting tcp proxy with local_port: {}, remote cid: {}, remote_port: {}", local_port, remote_cid, remote_port);

        proxies.spawn(async move {
            loop {
                match tcp_proxy.clone().accept(&listener).await {
                    Ok(_handler) => {
                        tracing::info!("Accepted tcp connection on proxy {:?}", tcp_proxy.desc());
                    },
                    Err(e) => {
                        tracing::error!("Error accepting tcp connection on proxy {:?}: {:?}", tcp_proxy.desc(), e);
                    }
                }
            }
        });
    }

    for vsock_proxy_config in config.vsock_proxies.iter() {
        let local_cid = vsock_proxy_config.local_vsock_cid;
        let local_port = vsock_proxy_config.local_vsock_port;
        let remote_host = vsock_proxy_config.remote_host.clone();
        let remote_port = vsock_proxy_config.remote_port;

        let ip_addr_type = proxy::IpAddrType::IPAddrMixed;
        let vsock_proxy = proxy::vsock::VsockProxy::new(local_cid, local_port, remote_host.clone(), remote_port, ip_addr_type).unwrap();
        let vsock_proxy = std::sync::Arc::new(vsock_proxy);

        let listener = vsock_proxy.listen().await.unwrap();
        tracing::info!("Starting vsock proxy with local_port: {}, remote_host: {}, remote_port: {}", local_port, remote_host, remote_port);

        proxies.spawn(async move {
            loop {
                match vsock_proxy.clone().accept(&listener).await {
                    Ok(_handler) => {
                        tracing::info!("Accepted vsock connection on proxy {:?}", vsock_proxy.desc());
                    },
                    Err(e) => {
                        tracing::error!("Error accepting vsock connection on proxy {:?}: {:?}", vsock_proxy.desc(), e);
                    }
                }
            }
        });
    }

	// wait for all the proxies to finish, which shall never happen
	while let Some(res) = proxies.join_next().await {
		_ = res.unwrap();
	}
	
}

// cargo run --package proxy --bin main -- run --cfg-path crates/proxy/config
#[tokio::main]
async fn main() {
	let cli = Cli::parse();
    let r = cli.command.execute().await;
    println!("proxy result: {:?}", r);
}
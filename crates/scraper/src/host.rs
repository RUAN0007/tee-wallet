use std::result::Result;
use crate::{
    errors::ScraperError,
    config::ScraperConfig,
};
 

#[cfg(target_os = "linux")]
pub async fn start(cfg : ScraperConfig) -> Result<(), ScraperError> {
    tracing::info!(
        "start to launch the sig server on host with config: {:?}",
        cfg,
    );

    // iterate over the vsock_proxies and start the vsock proxy
    let mut proxies = tokio::task::JoinSet::new();

    for vsock_proxy_config in cfg.host.vsock_proxies.iter() {
        let local_port = vsock_proxy_config.local_vsock_port;
        let remote_host = vsock_proxy_config.remote_host.clone();
        let remote_port = vsock_proxy_config.remote_port;

        let ip_addr_type = proxy::IpAddrType::IPAddrMixed;
        let host_cid = proxy::vsock::VSOCK_HOST_CID;
        let vsock_proxy = proxy::vsock::VsockProxy::new(host_cid, local_port, remote_host.clone(), remote_port, ip_addr_type).map_err(|e| ScraperError::VSockProxyError(e))?;
        let vsock_proxy = std::sync::Arc::new(vsock_proxy);

        let listener = vsock_proxy.listen().await.map_err(|e| ScraperError::VSockProxyError(e))?;
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

    let tcp_port = cfg.host.listen_port;
    let cid = cfg.enclave.cid;
    let vsock_port = cfg.enclave.grpc.vsock_port;

    let tcp_proxy = proxy::tcp::TcpProxy::new(tcp_port, cid, vsock_port).map_err(|e| ScraperError::TcpProxyError(e))?;
    let tcp_proxy = std::sync::Arc::new(tcp_proxy);

    proxies.spawn(async move {
        let listener = tcp_proxy.listen().await.map_err(|e| ScraperError::TcpProxyError(e)).unwrap();
        tracing::info!("Starting tcp proxy with local_port: {}, remote cid: {}, remote vsock port: {}", tcp_port, cid, vsock_port);
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

    // wait for all the proxies to finish, which shall never happen
    while let Some(res) = proxies.join_next().await {
        _ = res?;
    }

    return Ok(());
}
#[cfg(not(target_os = "linux"))]
pub async fn start(_cfg : ScraperConfig) -> Result<(), ScraperError> {
    panic!("Unsupported OS");
}
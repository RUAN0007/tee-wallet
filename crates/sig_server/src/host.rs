use std::result::Result;
use crate::{
    errors::SigServerError,
    config::SigServerConfig,
};
 

#[cfg(target_os = "linux")]
pub async fn start(cfg : SigServerConfig) -> Result<(), SigServerError> {
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

        let vsock_proxy = proxy::vsock::VsockProxy::new(local_port, remote_host.clone(), remote_port, ip_addr_type).map_err(|e| SigServerError::VSockProxyError(e))?;
        let vsock_proxy = std::sync::Arc::new(vsock_proxy);

        let listener = vsock_proxy.listen().await.map_err(|e| SigServerError::VSockProxyError(e))?;
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

    let tcp_proxy = proxy::tcp::TcpProxy::new(tcp_port, cid, vsock_port).map_err(|e| SigServerError::TcpProxyError(e))?;
    let tcp_proxy = std::sync::Arc::new(tcp_proxy);

    proxies.spawn(async move {
        let listener = tcp_proxy.listen().await.map_err(|e| SigServerError::TcpProxyError(e)).unwrap();
        tracing::info!("Starting tcp proxy with local_port: {}, remote cid: {}, remote vsock port: {}", tcp_port, cid, vsock_port);
        loop {
            match tcp_proxy.clone().accept(&listener).await {
                Ok(_) => {
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
pub async fn start(_cfg : SigServerConfig) -> Result<(), SigServerError> {
    panic!("Unsupported OS");
}


#[cfg(debug_assertions)] // for testing traffic between enclave and host
pub async fn echo(_cfg : SigServerConfig, port : &u16) -> Result<(), SigServerError> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    
    let tcp_port = *port;
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", tcp_port)).await.map_err(|_| SigServerError::TcpProxyError(format!("fail to listen to tcp echo server on port {}", tcp_port)))?;
    tracing::info!("Echo server listening on port {}", tcp_port);
    loop {
        let (mut socket, _) = listener.accept().await.map_err(|e| SigServerError::TcpProxyError(format!("fail to accept connection echo server on port {} for err {}", tcp_port, e)))?;
        tokio::spawn(async move {
            let (mut reader, mut writer) = socket.split();
            let mut buffer = vec![0; 1024];

            loop {
                match reader.read(&mut buffer).await {
                    Ok(0) => break, // Connection closed
                    Ok(n) => {
                        tracing::info!("Received and echo back data {} bytes from client: {:?}", n, &buffer[..n]);
                        if let Err(e) = writer.write_all(&buffer[..n]).await {
                            tracing::error!("Failed to send response: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to read from socket: {:?}", e);
                        break;
                    }
                }
            }
        });
    }
}
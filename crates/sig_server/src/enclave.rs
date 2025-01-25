use std::{net::SocketAddr,result::Result};
use rsa::pkcs1::EncodeRsaPublicKey;
use tonic::transport::Server;
use crate::{
    errors::SigServerError,
    config::SigServerConfig,
    service::attestation_svc::{
        attestation_server::AttestationServer
        , AttestationHandler},

};
use utils::crypto::init_rsa_keypair;
use rsa::{RsaPrivateKey, RsaPublicKey};
use once_cell::sync::Lazy;

pub static RSA_KEYPAIR: Lazy<(RsaPrivateKey, RsaPublicKey)> = Lazy::new(|| init_rsa_keypair()); // TODO: use nitro SDK to seed the keypair for stronger security

pub async fn start(cfg : SigServerConfig) -> Result<(), SigServerError> {
    let mut join_set = tokio::task::JoinSet::new();
    let tcp_port = cfg.enclave.grpc.tcp_port;
    let socket_addr : SocketAddr = format!("127.0.0.1:{}", tcp_port).parse().unwrap();

    // start the listener first, so that later proxy can connect. 
    let listener = tokio::net::TcpListener::bind(socket_addr).await.unwrap();
    
    #[cfg(target_os = "linux")]
    for tcp_proxy_config in cfg.enclave.tcp_proxies.iter() {
        let local_port = tcp_proxy_config.local_tcp_port;
        let remote_cid = tcp_proxy_config.remote_cid;
        let remote_port = tcp_proxy_config.remote_port;

        let tcp_proxy = proxy::tcp::TcpProxy::new(local_port, remote_cid, remote_port).map_err(|e| SigServerError::TcpProxyError(e))?;
        let tcp_proxy = std::sync::Arc::new(tcp_proxy);

        let listener = tcp_proxy.listen().await.map_err(|e| SigServerError::TcpProxyError(e))?;
        tracing::info!("Starting tcp proxy with local_port: {}, remote cid: {}, remote_port: {}", local_port, remote_cid, remote_port);

        join_set.spawn(async move {
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

    #[cfg(target_os = "linux")]
    {
        let vsock_port = cfg.enclave.grpc.vsock_port;
        let ip_addr_type = proxy::IpAddrType::IPAddrMixed;
        let localhost = "127.0.0.1".to_string();
        // forward traffic from vsock to grpc        
        let vsock_proxy = proxy::vsock::VsockProxy::new(vsock_port, localhost.clone(), tcp_port, ip_addr_type).map_err(|e| SigServerError::VSockProxyError(e))?;
        let vsock_proxy = std::sync::Arc::new(vsock_proxy);
        let listener = vsock_proxy.listen().await.map_err(|e| SigServerError::VSockProxyError(e))?;
        tracing::info!("Starting vsock proxy for grpc with local_port: {}, remote_host: {}, remote_port: {}", vsock_port, localhost, tcp_port);

        join_set.spawn(async move {
            loop {
                match vsock_proxy.clone().accept(&listener).await {
                    Ok(_) => {
                        tracing::info!("Accepted vsock connection for grpc on proxy {:?}", vsock_proxy.desc());
                    },
                    Err(e) => {
                        tracing::error!("Error accepting vsock connection for grpc on proxy {:?}: {:?}", vsock_proxy.desc(), e);
                    }
                }
            }
        });
    }

    let pk_bytes = hex::encode(RSA_KEYPAIR.1.to_pkcs1_der().unwrap().as_bytes());

    join_set.spawn(async move {
        tracing::info!(
            "start to launch the signing server on enclave with config: {:?} and pub key pkcs1 {:?}, PEM {:?}",
            cfg,
            pk_bytes,
            RSA_KEYPAIR.1.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF),
        );
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let mut s = Server::builder()
            .add_service(AttestationServer::new(AttestationHandler::default()));

        #[cfg(debug_assertions)]  
        {
            s = s.add_service(crate::service::test_svc::test_server::TestServer::new(crate::service::test_svc::TestHandler::default()));
        }

        _ = s.serve_with_incoming(incoming).await;
    });


    // wait for all the proxies and grpc server to finish, which shall never happen
    while let Some(res) = join_set.join_next().await {
        _ = res?;
    }

    return Ok(());
}
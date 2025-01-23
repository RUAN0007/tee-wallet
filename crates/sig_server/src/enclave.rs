use std::result::Result;
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

    #[cfg(target_os = "linux")]
    for tcp_proxy_config in cfg.enclave.tcp_proxies.iter() {
        let local_port = tcp_proxy_config.local_tcp_port;
        let remote_cid = tcp_proxy_config.remote_cid;
        let remote_port = tcp_proxy_config.remote_port;
        let num_workers = 1;

        let mut tcp_proxy = proxy::tcp::TcpProxy::new(local_port, remote_cid, remote_port, num_workers).map_err(|e| SigServerError::TcpProxyError(e))?;
        let listener = tcp_proxy.listen().map_err(|e| SigServerError::TcpProxyError(e))?;
        tracing::info!("Starting tcp proxy with local_port: {}, remote cid: {}, remote_port: {}", local_port, remote_cid, remote_port);

        join_set.spawn(async move {
            loop {
                match tcp_proxy.accept(&listener) {
                    Ok(_) => {
                        tracing::info!("Accepted tcp connection on proxy {:?}", tcp_proxy);
                    },
                    Err(e) => {
                        tracing::error!("Error accepting tcp connection on proxy {:?}: {:?}", tcp_proxy, e);
                    }
                }
            }
        });
    }

    join_set.spawn(async move {

        // let port = cfg.enclave.grpc.port;
        // #[cfg(target_os = "linux")]
        // let listener = tokio_vsock::VsockListener::bind(port).unwrap();

        // #[cfg(not(target_os = "linux"))]
        // let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await.unwrap();

        // let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        // let attestation_handler = AttestationHandler::default();
        // tracing::info!(
        //     "start to launch the sig server on enclave with config: {:?} and pub key {:?}",
        //     cfg,
        //     RSA_KEYPAIR.1 // TODO: 
        // );

        // _ = Server::builder()
        //     .add_service(AttestationServer::new(attestation_handler))
        //     .serve_with_incoming(incoming)
        //     .await;
    });


    // wait for all the proxies and grpc server to finish, which shall never happen
    while let Some(res) = join_set.join_next().await {
        _ = res?;
    }

    return Ok(());
}
use tonic::transport::Server;
use std::result::Result;
use once_cell::sync::Lazy;
use tonic_middleware::InterceptorFor;
use ed25519_dalek::SigningKey;

use crate::{
    errors::ScraperError,
    config::ScraperConfig,

    service::scraper_svc::{
        scraper_server::ScraperServer
        , ScraperHandler},
};

pub static ID_KEY: Lazy<SigningKey> = Lazy::new(|| {
    #[cfg(all(not(target_os = "linux"), debug_assertions))] 
    // for local testing. 
    let sk = {
        let sk_bytes : [u8;32] = hex::decode(utils::TEST_ED25519_SVC_SK_HEX).unwrap().try_into().unwrap();
        SigningKey::from_bytes(&sk_bytes)
    };


    #[cfg(target_os = "linux")] 
    let sk = {
        // use enclave-generated random seed to seed the keypair
        use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
        use aws_nitro_enclaves_nsm_api::api::{Request as NsmReq, Response as NsmResp};
        use rand::RngCore;

        let ctx = nsm_init();
        let response = nsm_process_request(
            ctx,
            NsmReq::GetRandom        
        );
        nsm_exit(ctx);
        let mut sk_bytes : [u8; 32] = [0; 32];
        match response {
            NsmResp::GetRandom { random } => {
                if random.len() < 32 {
                    tracing::warn!("the len of random is {}, less than 32, so we pad with OS-generated random bytes", random.len());
                    // copy the random bytes to the seed
                    sk_bytes[..random.len()].copy_from_slice(&random);
                    // pad the rest with OS-generated random bytes
                    let mut rng = rand::rngs::OsRng;
                    rng.fill_bytes(&mut sk_bytes[random.len()..]);
                } else {
                    tracing::info!("the len of random is {}, greater than 32, so we slice the front for seed", random.len());
                    sk_bytes.copy_from_slice(&random[..32]);
                }
            }
            e => {
                panic!("Failed to get random nonce from NSM: {:?}", e);
            }
        };
        SigningKey::from_bytes(&sk_bytes)
    };

    sk
});

pub async fn start(cfg : ScraperConfig) -> Result<(), ScraperError> {
    let mut join_set = tokio::task::JoinSet::new();
    let tcp_port = cfg.enclave.grpc.tcp_port;
    let socket_addr = format!("127.0.0.1:{}", tcp_port);
    println!("start to listen to grpc port: {:?}", socket_addr);

    // start the listener first, so that later proxy can connect. 
    let grpc_listener = tokio::net::TcpListener::bind(socket_addr).await.unwrap();
    
    #[cfg(target_os = "linux")]
    for tcp_proxy_config in cfg.enclave.tcp_proxies.iter() {
        let local_port = tcp_proxy_config.local_tcp_port;
        let remote_cid = tcp_proxy_config.remote_cid;
        let remote_port = tcp_proxy_config.remote_port;

        let tcp_proxy = proxy::tcp::TcpProxy::new(local_port, remote_cid, remote_port).map_err(|e| ScraperError::TcpProxyError(e))?;
        let tcp_proxy = std::sync::Arc::new(tcp_proxy);

        let listener = tcp_proxy.listen().await.map_err(|e| ScraperError::TcpProxyError(e))?;
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
        let tcp_port = cfg.enclave.grpc.tcp_port;
        let vsock_port = cfg.enclave.grpc.vsock_port;
        let ip_addr_type = proxy::IpAddrType::IPAddrMixed;
        let localhost = "127.0.0.1".to_string();
        // forward traffic from vsock to grpc        
        let vsock_proxy = proxy::vsock::VsockProxy::new(cfg.enclave.cid, vsock_port, localhost.clone(), tcp_port, ip_addr_type).map_err(|e| ScraperError::VSockProxyError(e))?;
        let vsock_proxy = std::sync::Arc::new(vsock_proxy);
        let listener = vsock_proxy.listen().await.map_err(|e| ScraperError::VSockProxyError(e))?;
        tracing::info!("Starting vsock proxy for grpc with local_port: {}, remote_host: {}, remote_port: {}", vsock_port, localhost, tcp_port);

        join_set.spawn(async move {
            loop {
                match vsock_proxy.clone().accept(&listener).await {
                    Ok(_handler) => {
                        tracing::info!("Accepted vsock connection for grpc on proxy {:?}", vsock_proxy.desc());
                    },
                    Err(e) => {
                        tracing::error!("Error accepting vsock connection for grpc on proxy {:?}: {:?}", vsock_proxy.desc(), e);
                    }
                }
            }
        });
    }

    let scraping_interval = std::time::Duration::from_secs(cfg.enclave.twitter.polling_interval_sec);
    let mut scraper_runner = crate::core::scraping_runner::ScrapingRunner::new("https://api.mainnet-beta.solana.com");

    join_set.spawn(async move {
        scraper_runner.run(scraping_interval).await
    });

    join_set.spawn(async move {
        tracing::info!(
            "start to launch the signing server on enclave with config: {:?} and ed25519 pub key {:?}",
            cfg,
            bs58::encode(ID_KEY.verifying_key().to_bytes()).into_string(), 
        );
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(grpc_listener);

        let scraper_service = ScraperServer::new(ScraperHandler::default());
        let auth_interceptor = utils::middleware::AuthInterceptor {};

        let mut s = Server::builder()
            .add_service(InterceptorFor::new(scraper_service, auth_interceptor.clone()));

        _ = s.serve_with_incoming(incoming).await.unwrap();
    });

    // wait for all the proxies and grpc server to finish, which shall never happen
    while let Some(res) = join_set.join_next().await {
        _ = res?;
    }

    return Ok(());
}
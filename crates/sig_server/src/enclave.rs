use std::result::Result;

use rsa::pkcs1::EncodeRsaPublicKey;
use tonic::transport::Server;
use crate::{
    errors::SigServerError,
    config::SigServerConfig,
    service::attestation_svc::{
        attestation_server::AttestationServer
        , AttestationHandler},

};
use rsa::{RsaPrivateKey, RsaPublicKey};
use once_cell::sync::Lazy;

pub static RSA_KEYPAIR: Lazy<(RsaPrivateKey, RsaPublicKey)> = Lazy::new(|| {
    #[cfg(all(not(target_os = "linux"), debug_assertions))] 
    let key_pair = {
        use rsa::pkcs1::DecodeRsaPrivateKey;
        // for local debugging purpose, we fix a keypair so that later attestaion document is always the same. 
        let sk_doc_bytes = "308204a30201000282010100bca7c71fff29eb2f0ef1fe31b662109255e9705c2ee01a8fb01c9acd55ad78fd5d1d78f9093860fc7956a4539d011e1fe3e8fc3da4e9fb7808487a74ce876c42318fe5c2b51319107086b1591e6517a29faa5cab8e61d77655a3b4df52f1779a6e77bedb18bffe2300c97ca3ac9f2504a874eaf44919796ea0bc37fba7af63a9596ad5c6a01e6e82ad5d0afc6647322303c9a65260908afede219bdb2080770e52045fb05a74d3a59123f47a8dd91366e2ea75c6de822bc97a023b77c2691da42bbf279882493190aefe11d8bfc160fae5d859af0e3a8d2e516fa4cc36a59eae718b4da0ac10abc49cc7cfa8be55996938aaef9e2b74ddfd61bcfd3f29631e0b0203010001028201002cb75ffd778fca0d176fc89ea3ea4e9f40f9da061f9e42ed7802efb667ee7c5521b310af86bdf44f23bba3aba5f553dc9f3ae43f004dedab1fdb7e1b1db0ffba18e150c67c0110d9d2b23a6b334726f906fb6c87c571ef8e3ef254b6f28405a37737aee763d06e3e81bb406dd346cd91731473747fb7280f4ece0e3efa1a1a76eaa4334dfb3dd9b058097289585846329145271a296fde5c601becbbb3ee00e4aac5ca4deed0c7a84bcc798b8122f4231310c4eca180c3bfaa5f7d80bab208464f1061cba607984df09eb61ea9ec4f5b3adcf11cab17684fae85051e8eb3aeb0d0f10bda3b7712406bffa4d91774e77cd3a5d3091f9f6f8446627b5a3a5b68e102818100c28ae1688577d98e45b16e0a62dfb54856e550741a878201e859d8b2e8d9d4e4e8433d6f54be73faaed26927cbf655c8049f4ac5e09830657b474dca4b1fd3681ed2e19d354f00f39985e3dfc53453ef8ebf2ff7d345f4035edfebb1dcbdb6422e6715b4f88a44f4d7f378eddd0210ae71c445c0f78854b75e65382638f79dc902818100f840cab4058f21ca16c1d191c175283b6beeb63044e195dadf2a332942dcb5096a1c0505e81a447da395413ac8c44c34742a462c3a703d804e3e5782273f38a0da59d9df5a80dbd9279631a4347a81a199df51921d30fda50ceaf65108e2e87298bda24b5cc0bed2b2bbbc98dc489369be1f79a936d0b3016ccd6018ae24b7330281805d5b7c5446487f7490e9569f51577d8d5b75ec27eb5b3ffe5e5c4f6b7be69d0dc4900ff94f379e3c9c8c88bdfa591a4d443a950d647c642d2efdc6ccdf44449560c55e53acf35ec787d302c9adbf30d073363874bb448496e17e9f82d925894335356eeb4ba23ef92870c485915b9e59b86ab1f6aa5318246efe2ff5d7bcac5102818014611d42d20202001906283212f38f2df19a53127b55197c323dc09d6e83b7c8e21112c87d594aae15b3b6fb20681ce9616fe6fad2814c4b30212605e53ae7672d059b411ea8dd6362408e2ab0b42dd81a4d9ee0a3ccd5c5aaddcf02affc10a0f7b0f995be338476bf7d71ea0a8b5aae9f90ede7da3c1fb5ca3cc1dac4d0f6c902818100ba15a801a5940c3c430c49730148bdcc2e09fdf94f8618ed6acc29ca0ecf5ca034225974d367071a7357e3d6e240abc0ea70b5a9f6bc39a70199cf061c0f089b7232873557feb55da21c17a9a906f88058760c2ed0881031eb8dc2bbcc9f988214a01effe21b5e6c211c631eacd8101c0630292af201d384f31ee1dd2bc2029c";

        let sk = RsaPrivateKey::from_pkcs1_der(&hex::decode(sk_doc_bytes).unwrap()).unwrap();    
        let pk = sk.to_public_key();
        (sk, pk)
    };

    #[cfg(target_os = "linux")] 
    let key_pair = {
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
        let mut seed : [u8; 32] = [0; 32];
        match response {
            NsmResp::GetRandom { random } => {
                if random.len() < 32 {
                    tracing::warn!("the len of random is {}, less than 32, so we pad with OS-generated random bytes", random.len());
                    // copy the random bytes to the seed
                    seed[..random.len()].copy_from_slice(&random);
                    // pad the rest with OS-generated random bytes
                    let mut rng = rand::rngs::OsRng;
                    rng.fill_bytes(&mut seed[random.len()..]);
                } else {
                    tracing::info!("the len of random is {}, greater than 32, so we slice the front for seed", random.len());
                    seed.copy_from_slice(&random[..32]);
                }
            }
            e => {
                panic!("Failed to get random nonce from NSM: {:?}", e);
            }
        };

        utils::crypto::init_rsa_keypair_with_seed(seed)
    };

    key_pair
});

pub async fn start(cfg : SigServerConfig) -> Result<(), SigServerError> {
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
        let tcp_port = cfg.enclave.grpc.tcp_port;
        let vsock_port = cfg.enclave.grpc.vsock_port;
        let ip_addr_type = proxy::IpAddrType::IPAddrMixed;
        let localhost = "127.0.0.1".to_string();
        // forward traffic from vsock to grpc        
        let vsock_proxy = proxy::vsock::VsockProxy::new(cfg.enclave.cid, vsock_port, localhost.clone(), tcp_port, ip_addr_type).map_err(|e| SigServerError::VSockProxyError(e))?;
        let vsock_proxy = std::sync::Arc::new(vsock_proxy);
        let listener = vsock_proxy.listen().await.map_err(|e| SigServerError::VSockProxyError(e))?;
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

    let pk_bytes = hex::encode(RSA_KEYPAIR.1.to_pkcs1_der().unwrap().as_bytes());

    join_set.spawn(async move {
        tracing::info!(
            "start to launch the signing server on enclave with config: {:?} and pub key pkcs1 {:?}, PEM {:?}",
            cfg,
            pk_bytes,
            RSA_KEYPAIR.1.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF),
        );
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(grpc_listener);

        let mut s = Server::builder()
            .add_service(AttestationServer::new(AttestationHandler::default()));

        #[cfg(debug_assertions)]  
        {
            s = s.add_service(crate::service::test_svc::test_server::TestServer::new(crate::service::test_svc::TestHandler::default()));
        }

        _ = s.serve_with_incoming(incoming).await.unwrap();
    });


    // wait for all the proxies and grpc server to finish, which shall never happen
    while let Some(res) = join_set.join_next().await {
        _ = res?;
    }

    return Ok(());
}
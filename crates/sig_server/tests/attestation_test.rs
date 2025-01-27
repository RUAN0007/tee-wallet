#[cfg(test)]
mod tests {
    use proxy::tcp2tcp::Tcp2TcpProxy;
	use tonic::transport::Server;
    use tonic::Request;
    use tokio::sync::OnceCell;
    use attestation_client::AttestationClient;
	use sig_server::service::attestation_svc::{
			attestation_server::AttestationServer, 
			AttestationHandler};

	tonic::include_proto!("attestation");

	const URL : &str = "http://127.0.0.1:50051";

    static SERVER : OnceCell<()> = OnceCell::const_new();

    async fn start_server() {
		const ADDR : &str = "127.0.0.1:50051";
        let listener = tokio::net::TcpListener::bind(ADDR).await.unwrap();

        tokio::spawn( async move {
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AttestationServer::new(AttestationHandler::default()))
            .serve_with_incoming(stream)
            .await
            .unwrap();
        });
	}

    #[tokio::test]
    async fn test_get_attestation_doc() {
        SERVER.get_or_init(start_server).await;
        const URL : &str = "http://ec2-3-106-196-114.ap-southeast-2.compute.amazonaws.com:9000";
        let mut client = AttestationClient::connect(URL).await.unwrap();

        let request = Request::new(AttestationReq {
            nonce: vec![1, 2, 3],
        });
		let response = client.get_attestation_doc(request).await;

        // assert_eq!(response.code, 1);
		// let response_inner = response.into_inner(); // Unwrap the response to get the inner message
	
        match response {
            Err(e) => {
                assert_eq!(e.code(), tonic::Code::Internal);
                assert_eq!(e.message(), sig_server::errors::ERR_INVALID_NSM_RESP); // Example assertion, replace with actual expected error message
            },
            Ok(r) => panic!("Expected an error, but got a successful response {:?}", r),
        }
    }

    #[tokio::test]
    async fn test_get_attestation_doc_via_proxy() {
        let trace_cfg = trace::TraceConfig { 
            prefix: "proxy".to_owned(), 
            dir: "log".to_owned(), 
            level: tracing::Level::DEBUG, 
            console: true, flame: false };
    
        let _g = trace::init_tracing(trace_cfg);

        SERVER.get_or_init(start_server).await;
        let t2t_proxy = Tcp2TcpProxy::new(40051, "127.0.0.1".to_owned(), 50051).unwrap();
        let t2t_proxy = std::sync::Arc::new(t2t_proxy);
        let t2t_lister = t2t_proxy.listen().await.unwrap();

        let mut handlers = tokio::task::JoinSet::new();
        handlers.spawn(async move {
            loop {
                match t2t_proxy.clone().accept(&t2t_lister).await {
                    Ok(_handler) => {
                        tracing::info!("Accepted vsock connection on proxy {:?}", t2t_proxy.desc());
                    },
                    Err(e) => {
                        tracing::error!("Error accepting vsock connection on proxy {:?}: {:?}", t2t_proxy.desc(), e);
                    }
                }
            }
        });

        // let _proxy_handler = tokio::spawn(async move {
        //     let h = t2t_proxy.accept(&t2t_lister).await.unwrap(); 
        //     h.await.unwrap();
        // });

	    const URL : &str = "http://127.0.0.1:40051";
        let mut client = AttestationClient::connect(URL).await.unwrap();

        let request = Request::new(AttestationReq {
            nonce: vec![1, 2, 3],
        });
		let response = client.get_attestation_doc(request).await;

        // assert_eq!(response.code, 1);
		// let response_inner = response.into_inner(); // Unwrap the response to get the inner message
	
        match response {
            Err(e) => {
                assert_eq!(e.code(), tonic::Code::Internal);
                assert_eq!(e.message(), sig_server::errors::ERR_INVALID_NSM_RESP); // Example assertion, replace with actual expected error message
            },
            Ok(_) => panic!("Expected an error, but got a successful response"),
        }
        // tokio::time::sleep(tokio::time::Duration::from_secs(1000)).await;
        while let Some(res) = handlers.join_next().await {
            tracing::info!("handler finished");
        }
    }

    #[tokio::test]
    async fn test_task_lifetime() {
        let trace_cfg = trace::TraceConfig { 
            prefix: "proxy".to_owned(), 
            dir: "log".to_owned(), 
            level: tracing::Level::DEBUG, 
            console: true, flame: false };
    
        let _g = trace::init_tracing(trace_cfg);

        {
            for c in 0..2 {

                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                let _h = tokio::spawn(async move {
                    for i in 0..10 {
                        tracing::debug!("{} count: {}", c, i);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                });
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        }
        tracing::debug!("proxy handler finished");
        tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
    }
}
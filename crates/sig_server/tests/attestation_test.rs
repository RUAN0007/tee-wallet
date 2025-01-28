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
    use attestation_doc_validation::attestation_doc::decode_attestation_document;

	tonic::include_proto!("attestation");

    const HOST : &str = "127.0.0.1";
    const PORT : u16 = 50051;

    static SERVER : OnceCell<()> = OnceCell::const_new();

    async fn start_server() {
		let addr : String = format!("{}:{}", HOST, PORT);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

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
    async fn test_get_attestation_doc_via_proxy() {
        let trace_cfg = trace::TraceConfig { 
            prefix: "proxy".to_owned(), 
            dir: "log".to_owned(), 
            level: tracing::Level::DEBUG, 
            console: true, flame: false };
    
        let _g = trace::init_tracing(trace_cfg);

        let proxy_port = 40051;

        SERVER.get_or_init(start_server).await;
        let t2t_proxy = Tcp2TcpProxy::new(proxy_port, HOST.to_owned(), PORT).unwrap();

        // let remote_host : &str = "ec2-13-239-111-212.ap-southeast-2.compute.amazonaws.com";
        // let port = 9000;
        // let t2t_proxy = Tcp2TcpProxy::new(proxy_port, remote_host.to_owned(), port).unwrap();

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

	    let url  = format!("http://127.0.0.1:{}", proxy_port);
        let mut client = AttestationClient::connect(url).await.unwrap();
        let nonce = vec![1, 2, 3];
        let request = Request::new(AttestationReq {
            nonce: nonce.clone(),
        });
		let response = client.get_attestation_doc(request).await;
        let attestation_doc_bytes = response.unwrap().into_inner().doc;

        let attestatation_doc = decode_attestation_document(&attestation_doc_bytes);
        let (_,  attestation_doc) = attestatation_doc.unwrap();

        // If the doc is from a valid NSM, the following assertion should pass. 
        // assert!(attestation_doc_validation::validate_attestation_doc}(&attestation_doc_bytes).is_ok());
        assert_eq!(attestation_doc.nonce.unwrap(), nonce);
        assert_eq!(attestation_doc.user_data.unwrap(), b"GET_ATTESTATION_DOC");
    }
}
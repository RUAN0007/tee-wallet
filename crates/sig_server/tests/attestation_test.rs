#[cfg(test)]
mod tests {
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
    }
}
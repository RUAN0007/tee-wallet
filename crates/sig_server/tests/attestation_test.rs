#[cfg(test)]
mod tests {

	use tokio::{io::Join, task::JoinHandle};
	use tonic::transport::Server;
    use tonic::Request;
	use once_cell::sync::Lazy;

    use attestation_client::AttestationClient;
	use sig_server::service::attestation_svc::{
			attestation_server::AttestationServer, 
			AttestationHandler};

	tonic::include_proto!("attestation");

	const URL : &str = "http://[::1]:50051";

	static SERVER_HANDLER: Lazy<JoinHandle<()>> = Lazy::new(|| {
		const ADDR : &str = "[::1]:50051";
        let addr = ADDR.parse().unwrap();
        let attestation_handler = AttestationHandler::default();

        tokio::spawn(async move {
            Server::builder()
                .add_service(AttestationServer::new(attestation_handler))
                .serve(addr)
                .await
                .unwrap();
        })
	});

    #[tokio::test]
    async fn test_get_attestation_doc() {
        let mut client = AttestationClient::connect(URL).await.unwrap();

        let request = Request::new(AttestationReq {
        });
		let response = client.get_attestation_doc(request).await.unwrap();
		let response_inner = response.into_inner(); // Unwrap the response to get the inner message
	
		assert_eq!(response_inner.doc, vec![1, 2, 3]); // Example assertion, replace with actual expected value
	}
}
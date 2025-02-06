#[cfg(test)]
mod tests {
	use rsa::RsaPublicKey;
    use utils::crypto::{encrypt, init_rsa_keypair};
    use rsa::pkcs1::DecodeRsaPublicKey;
	use tonic::transport::Server;
    use tonic::Request;
    use tokio::sync::OnceCell;
	use sig_server::service::attestation_svc::{
			attestation_server::AttestationServer, 
			AttestationHandler};
	use sig_server::service::test_svc::{
			test_server::TestServer, 
			TestHandler};
	use sig_server::service::authorization_svc::{
			authorization_server::AuthorizationServer, 
			AuthorizationHandler};
    use attestation_doc_validation::attestation_doc::decode_attestation_document;

    tonic::include_proto!("attestation");
    tonic::include_proto!("authorization");
    tonic::include_proto!("sign");

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
            .add_service(AuthorizationServer::new(AuthorizationHandler::default()))
            .serve_with_incoming(stream)
            .await
            .unwrap();
        });
	}

    #[tokio::test]
    async fn test_example() {
        SERVER.get_or_init(start_server).await;

        let mut attestation_cli = AttestationClient::connect(URL).await.unwrap();
        let nonce = vec![1, 2, 3];
        let request = Request::new(AttestationReq {
            nonce: nonce.clone(),
        });
		let response = attestation_cli.get_attestation_doc(request).await;

        let attestation_doc_bytes = response.unwrap().into_inner().doc;

        let attestatation_doc = decode_attestation_document(&attestation_doc_bytes);
        let (_,  attestation_doc) = attestatation_doc.unwrap();

        let pk_bytes = attestation_doc.public_key.unwrap();
        let public_key = RsaPublicKey::from_pkcs1_der(&pk_bytes).expect("fail for pkcs der");
        assert_eq!(1 + 1, 2);

    }
}
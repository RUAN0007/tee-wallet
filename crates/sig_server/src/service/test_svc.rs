use tonic::{Request, Response, Status};
use crate::service::test_svc::test_server::Test;
use crate::enclave;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use utils::crypto::decrypt;

// Import the generated proto code
tonic::include_proto!("test");

// Define the service handler struct
#[derive(Default)]
pub struct TestHandler;

// Implement the service trait for the handler struct
#[tonic::async_trait]
impl Test for TestHandler {
    async fn connect_remote_host(
        &self,
        request: Request<ConnectRemoteHostReq>,
    ) -> Result<Response<ConnectRemoteHostResp>, Status> {
        let req = request.into_inner();
        let addr = format!("{}:{}", req.host, req.port);
        tracing::debug!("Connecting to remote host at {}", addr);
        let mut stream = TcpStream::connect(addr.clone()).await.map_err(|e| Status::internal(format!("Failed to connect: {:?}", e)))?;
        tracing::debug!("remote host at {} connected", addr);
		let msg = req.msg.as_bytes();
        stream.write_all(msg).await.map_err(|e| Status::internal(format!("Failed to send message {}: {:?}", req.msg, e)))?;
        
        tracing::debug!("finish writing msg {}", req.msg);
        let duration = Duration::from_millis(req.timeout_ms as u64);
        let mut buffer = vec![0; 1024];
        
        tracing::debug!("wait to read {}", req.msg);
        let n = timeout(duration, stream.read(&mut buffer)).await.map_err(|_| Status::internal("Timed out waiting for message"))??;
        let incoming_msg = String::from_utf8_lossy(&buffer[..n]).to_string();
        tracing::debug!("read incoming msg {}", incoming_msg);
        
        let reply = ConnectRemoteHostResp { msg: incoming_msg };
        Ok(Response::new(reply))
    }

    async fn decrypt(
        &self,
        request: Request<DecryptReq>,
    ) -> Result<Response<DecryptResp>, Status> {
        // Extract the request message
        let req = request.into_inner();

		match decrypt(&enclave::RSA_KEYPAIR.0, &req.ciphertext) {
			Ok(plaintext) => {
				let reply = DecryptResp {
					plaintext,
				};
				return Ok(Response::new(reply));
			},
			Err(e) => {
				return Err(Status::invalid_argument(format!("fail to decrypt for error: {}", e)));
			}
		}
    }
}

#[cfg(test)]
mod tests {
    use rsa::RsaPublicKey;
    use utils::crypto::{encrypt, init_rsa_keypair};
    use rsa::pkcs1::DecodeRsaPublicKey;
	use tonic::transport::Server;
    use tonic::Request;
    use tokio::sync::OnceCell;
    use attestation_client::AttestationClient;
    use test_client::TestClient;
	use crate::service::attestation_svc::{
			attestation_server::AttestationServer, 
			AttestationHandler};
	use crate::service::test_svc::{
			test_server::TestServer, 
			TestHandler};
    use attestation_doc_validation::attestation_doc::decode_attestation_document;

	tonic::include_proto!("attestation");
	tonic::include_proto!("test");

	const URL : &str = "http://127.0.0.1:50051";

    static SERVER : OnceCell<()> = OnceCell::const_new();

    async fn start_server() {
		const ADDR : &str = "127.0.0.1:50051";
        let listener = tokio::net::TcpListener::bind(ADDR).await.unwrap();

        tokio::spawn( async move {
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AttestationServer::new(AttestationHandler::default()))
            .add_service(TestServer::new(TestHandler::default()))
            .serve_with_incoming(stream)
            .await
            .unwrap();
        });
	}

    #[tokio::test]
    async fn test_encryption_with_attest_doc_pk() {
        SERVER.get_or_init(start_server).await;

        // edit the URL to point to the correct server
        // const URL : &str = "http://ec2-13-236-193-139.ap-southeast-2.compute.amazonaws.com:9000";
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

        let data = b"hello world";
        let encrypted_data = encrypt(&public_key, data).unwrap();

        let request = Request::new(DecryptReq {
            ciphertext: encrypted_data,
        });

        let mut attestation_cli = TestClient::connect(URL).await.unwrap();
        let response = attestation_cli.decrypt(request).await;
        assert_eq!(response.unwrap().into_inner().plaintext, data);

        let (_, another_pub_key) = init_rsa_keypair();
        let another_encrypted_data = encrypt(&another_pub_key, data).unwrap();

        let request = Request::new(DecryptReq {
            ciphertext: another_encrypted_data,
        });
        let response = attestation_cli.decrypt(request).await;

        match response {
            Err(e) => {
                assert_eq!(e.code(), tonic::Code::InvalidArgument);
            },
            Ok(_) => panic!("Expected an error when decrypting a ciphertext encrypted by another pubkey, but got a successful response"),
        }

    }
}
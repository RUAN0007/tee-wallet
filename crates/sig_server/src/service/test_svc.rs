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
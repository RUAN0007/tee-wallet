use std::result::Result;
use tonic::transport::Server;
use tonic::transport::Error;
use crate::{
    errors::SigServerError,
    config::SigServerConfig,
    service::attestation_svc::{
        attestation_server::AttestationServer
        , AttestationHandler},
};

pub async fn start(cfg : SigServerConfig) -> Result<(), SigServerError> {
    tracing::info!(
        "start to launch the sig server with config: {:?}",
        cfg
    );

    let addr = "[::1]:50051".parse().unwrap();
    let attestation_handler = AttestationHandler::default();

    Server::builder()
        .add_service(AttestationServer::new(attestation_handler))
        .serve(addr)
        .await.map_err(|e : Error|{SigServerError::ServerError(e)})?;

    return Ok(());
}
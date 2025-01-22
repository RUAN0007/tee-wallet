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
use utils::crypto::init_rsa_keypair;
use rsa::{RsaPrivateKey, RsaPublicKey};
use once_cell::sync::Lazy;

pub static RSA_KEYPAIR: Lazy<(RsaPrivateKey, RsaPublicKey)> = Lazy::new(|| init_rsa_keypair());

pub async fn start(cfg : SigServerConfig) -> Result<(), SigServerError> {
    tracing::info!(
        "start to launch the sig server with config: {:?} and pub key {:?}",
        cfg,
        RSA_KEYPAIR.1 // TODO: 
    );

    let addr = "[::1]:50051".parse().unwrap();
    let attestation_handler = AttestationHandler::default();

    Server::builder()
        .add_service(AttestationServer::new(attestation_handler))
        .serve(addr)
        .await.map_err(|e : Error|{SigServerError::ServerError(e)})?;

    return Ok(());
}
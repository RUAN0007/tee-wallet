
use rsa::pkcs1::EncodeRsaPublicKey;
use tonic::{Request, Response, Status};
use crate::service::authorization_svc::authorization_server::Authorization;
use crate::enclave;
use crate::errors;

use serde_bytes::ByteBuf;
use std::time::Instant;
use prost::Message;
use utils::crypto::decrypt;
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;

tonic::include_proto!("authorization");

#[derive(Debug, Default)]
pub struct AuthorizationHandler {}
#[tonic::async_trait]
impl Authorization for AuthorizationHandler {
    async fn authorize(
        &self,
        request: Request<AuthorizationReq>,
    ) -> Result<Response<AuthorizationResp>, Status> {
        let signature = request.metadata().get("X-Signature").ok_or(Status::unauthenticated("No signature"))?.to_str().map_err(|_| Status::unauthenticated("Invalid signature"))?;
        let signature = hex::decode(signature).map_err(|_| Status::unauthenticated("Fail to hex decode signature"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature).map_err(|_| Status::unauthenticated("Invalid signature"))?;

        let key_type = request.get_ref().key_type;
        if key_type == KeyType::Secp256k1 as i32{
           return Err(Status::unimplemented("Secp256k1 not supported")); 
        }
        let user_sk = decrypt(&enclave::RSA_KEYPAIR.0, request.get_ref().sk_ciphertext.as_slice())
            .map_err(|e| Status::invalid_argument("Fail to decrypt the private key"))?;
        let user_sk: [u8; 32] = user_sk.as_slice().try_into().map_err(|_| Status::invalid_argument("Invalid private key length"))?;
        let user_sk = SigningKey::from_bytes(&user_sk);

        let user_pk = user_sk.verifying_key();
        user_pk.verify(request.get_ref().as_slice(), &signature)
            .map_err(|_| Status::unauthenticated("Invalid signature"))?;

        let raw_payload : Vec<u8> = request.get_ref().encode_to_vec();

        // Log or use the raw payload as needed
        println!("Raw payload: {:?}", raw_payload);
        Err(Status::internal("N.A."))
    }
}

use rsa::pkcs1::EncodeRsaPublicKey;
use solana_sdk::bs58;
use tonic::body;
use tonic::{Request, Response, Status};
use crate::service::authorization_svc::authorization_server::Authorization;
use crate::enclave;
use crate::errors;
use crate::service::auth_registry::AuthRecord;
use crate::service::auth_registry::AuthRegistry;
use crate::service::auth_registry::AUTH_REGISTRY;

use serde_bytes::ByteBuf;
use std::time::Instant;
use std::time::SystemTime;
use prost::Message;
use utils::crypto::{decrypt, ed25519_pk_to_addr};
use ed25519_dalek::SigningKey;
use ed25519_dalek::Verifier;
use crate::service::SIG_HEADER;
use utils::middleware::header;

tonic::include_proto!("authorization");

#[derive(Debug, Default)]
pub struct AuthorizationHandler {}
#[tonic::async_trait]
impl Authorization for AuthorizationHandler {
    async fn authorize(
        &self,
        request: Request<AuthorizationReq>,
    ) -> Result<Response<AuthorizationResp>, Status> {

        let curve = request.metadata().get(header::CURVE).ok_or(Status::unauthenticated("No curve"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid curve due to error {:?}", e)))?;

        if curve != header::ED25519 {
            return Err(Status::unauthenticated("curve not supported"));
        }

        utils::middleware::validate_body_hash(&request)?;

        // verifiy user pub key
        let user_pk_in_header = request.metadata().get(header::PUBKEY).ok_or(Status::unauthenticated("No pub key"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid pub key due to error {:?}", e)))?;

        let user_sk_vec = decrypt(&enclave::RSA_KEYPAIR.0, request.get_ref().sk_ciphertext.as_slice())
            .map_err(|e| Status::invalid_argument(format!("Fail to decrypt the private key due to error {:?}", e)))?;
        let user_sk: [u8; 32] = user_sk_vec.as_slice().try_into().map_err(|_| Status::invalid_argument("Invalid private key length"))?;
        let user_pk = SigningKey::from_bytes(&user_sk).verifying_key();
        let user_pk_bs58 = bs58::encode(user_pk.to_bytes()).into_string();
        if user_pk_in_header != user_pk_bs58 {
            return Err(Status::unauthenticated("Public key mismatch"));
        }


        let start_at = request.get_ref().start_at
        .map_or(Ok(SystemTime::now()), |t| {SystemTime::try_from(t).map_err(|e| Status::invalid_argument(format!("fail to parse start_at timestamp to SystemTime due to error {:?}", e)))})?;

        let end_at = request.get_ref().end_at.ok_or(Status::invalid_argument("end_at is required"))?;
        let end_at : SystemTime = SystemTime::try_from(end_at).map_err(|e| Status::invalid_argument(format!("fail to parse start_at timestamp to SystemTime due to error {:?}", e)))?;

        let svc_type = ServiceType::from_i32(request.get_ref().svc_type).ok_or(Status::invalid_argument("Invalid service type"))?;

        let addr = ed25519_pk_to_addr(&user_pk);
        let auth_record = AuthRecord {
            addr: addr,
            svc_type: svc_type, 
            start_at: start_at,
            end_at: end_at,
            condition: request.get_ref().condition.clone(),
            action: request.get_ref().action.clone(),
            sk: user_sk_vec,
            key_type: KeyType::Ed25519,
        };
        let auth_id = {
            let mut w = AUTH_REGISTRY.write().map_err(|e| Status::internal(format!("Fail to lock AUTH_REGISTRY due to error {:?}", e)))?;
            w.add(auth_record).map_err(|e| Status::internal(format!("Fail to add auth record due to error {:?}", e)))?
        };
        let reply = AuthorizationResp {
            id: auth_id,
        };
        Ok(Response::new(reply))
    }
}
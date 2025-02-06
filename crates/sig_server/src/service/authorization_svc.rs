
use rsa::pkcs1::EncodeRsaPublicKey;
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

tonic::include_proto!("authorization");

#[derive(Debug, Default)]
pub struct AuthorizationHandler {}
#[tonic::async_trait]
impl Authorization for AuthorizationHandler {
    async fn authorize(
        &self,
        request: Request<AuthorizationReq>,
    ) -> Result<Response<AuthorizationResp>, Status> {
        let key_type = KeyType::from_i32(request.get_ref().key_type).ok_or(Status::invalid_argument("Invalid key type"))?;
        if key_type == KeyType::Secp256k1 {
           return Err(Status::unimplemented("Secp256k1 not supported")); 
        }

        let signature = request.metadata().get(SIG_HEADER).ok_or(Status::unauthenticated("No signature"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid signature due to error {:?}", e)))?;
        let signature = hex::decode(signature).map_err(|e| Status::unauthenticated(format!("Fail to hex decode signature due to error {:?}", e)))?;
        let signature : [u8; 64] = signature.as_slice().try_into().map_err(|_| Status::unauthenticated("Invalid signature length"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&signature);

        let user_sk = decrypt(&enclave::RSA_KEYPAIR.0, request.get_ref().sk_ciphertext.as_slice())
            .map_err(|e| Status::invalid_argument(format!("Fail to decrypt the private key due to error {:?}", e)))?;
        let user_sk: [u8; 32] = user_sk.as_slice().try_into().map_err(|_| Status::invalid_argument("Invalid private key length"))?;
        let user_sk = SigningKey::from_bytes(&user_sk);

        let user_pk = user_sk.verifying_key();
        user_pk.verify(&request.get_ref().encode_to_vec(), &signature)
            .map_err(|e| Status::unauthenticated(format!("Fail to verify signature due to error {:?}", e)))?;

        let raw_payload : Vec<u8> = request.get_ref().encode_to_vec();

        let start_at = request.get_ref().start_at
        .map_or(Ok(SystemTime::now()), |t| {SystemTime::try_from(t).map_err(|e| Status::invalid_argument(format!("fail to parse start_at timestamp to SystemTime due to error {:?}", e)))})?;

        let end_at = request.get_ref().end_at.ok_or(Status::invalid_argument("end_at is required"))?;
        let end_at : SystemTime = SystemTime::try_from(end_at).map_err(|e| Status::invalid_argument(format!("fail to parse start_at timestamp to SystemTime due to error {:?}", e)))?;

        let principal = Principal::from_i32(request.get_ref().principal).ok_or(Status::invalid_argument("Invalid principal"))?;

        let addr = ed25519_pk_to_addr(&user_pk);
        let auth_record = AuthRecord {
            addr: addr,
            principal: principal, 
            start_at: start_at,
            end_at: end_at,
            condition: request.get_ref().condition.clone(),
            action: request.get_ref().action.clone(),
            sk: user_sk.to_bytes().to_vec(), 
            key_type: key_type, 
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
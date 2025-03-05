
use tonic::{Request, Response, Status};
use crate::service::signing_svc::signing_server::Signing;
use crate::service::authorization_svc::Strategy;
use crate::errors::SigServerError;
use crate::service::auth_registry::AUTH_REGISTRY;

use solana_sdk::transaction::VersionedTransaction;
use solana_sdk::message::VersionedMessage;
use solana_sdk::signer::keypair::Keypair;

use std::time::SystemTime;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use crate::config::SigServerConfig;
use solana_sdk::bs58;
use utils::middleware::ed25519_pk_from_header;
use solana_sdk::signature::SeedDerivable;

tonic::include_proto!("signing");

#[derive(Debug, Default)]
pub struct SigningHandler {
    trusted_svcs: HashMap<VerifyingKey, Strategy>,
}

impl SigningHandler {
    pub fn new(cfg : &SigServerConfig) -> Result<Self, SigServerError> {
        let mut trusted_svcs =  HashMap::new();

        // for trusted_svc in cfg.enclave.trusted_services.iter() {
        //     let pub_key : Vec<u8> = bs58::decode(&trusted_svc.pub_key).into_vec().map_err(|e| {
        //         SigServerError::ConfigParameterError("trusted_services.pub_key".to_string(), format!("Fail to decode base58 encoded public key {} due to error {:?}", trusted_svc.pub_key, e).to_string())
        //     })?;

        //     let pub_key : [u8;32] = pub_key.as_slice().try_into().map_err(|e| {
        //         SigServerError::ConfigParameterError("trusted_services.pub_key".to_string(), format!("Fail to convert base58 decoded public key to array due to error {:?}", e).to_string())
        //     })?;

        //     let pub_key = VerifyingKey::from_bytes(&pub_key).map_err(|e| {
        //         SigServerError::ConfigParameterError("trusted_services.pub_key".to_string(), format!("Fail to create ed25519 verifying key from bytes due to error {:?}", e).to_string())
        //     })?;

        //     let strategy = Strategy::from_str_name(&trusted_svc.strategy).ok_or_else(|| {
        //         SigServerError::ConfigParameterError("trusted_services.strategy".to_string(), format!("Fail to parse service type {}", trusted_svc.strategy).to_string())
        //     })?;

        //     trusted_svcs.insert(pub_key, strategy);
        // }

        Ok(Self {
            trusted_svcs
        })
    }
}

#[tonic::async_trait]
impl Signing for SigningHandler {
    async fn solana_sign(
        &self,
        request: Request<SolanaSignReq>,
    ) -> Result<Response<SolanaSignResp>, Status> {
        utils::middleware::validate_body_hash(&request)?;
        let svc_pk = ed25519_pk_from_header(&request)?;

        let strategy = self.trusted_svcs.get(&svc_pk).ok_or(Status::invalid_argument("Service not trusted"))?;

        let user_addr = request.get_ref().user_addr.clone();
        let auth_record = {
            let r = AUTH_REGISTRY.read().map_err(|e| Status::internal(format!("Fail to get rlock AUTH_REGISTRY due to error {:?}", e)))?;

            r.search(&user_addr, *strategy, "", "").ok_or(Status::unauthenticated("User not authorized"))?
        };

        let current_time = SystemTime::now();

        if current_time < auth_record.start_at || current_time > auth_record.end_at {
            return Err(Status::unauthenticated("Authorization record is not valid at the current time"));
        }
        let key_pair = Keypair::from_seed(&auth_record.sk).map_err(|e| Status::internal(format!("Fail to create keypair from bytes due to error {:?}", e)))?;
        let versioned_msg = bincode::deserialize::<VersionedMessage>(&request.get_ref().versioned_msg).map_err(|e| Status::invalid_argument(format!("Fail to create versioned message from slice due to error {:?}", e)))?;

        let signed_txn = VersionedTransaction::try_new(versioned_msg, &[&key_pair]).map_err(|e| Status::internal(format!("Fail to sign transaction due to error {:?}", e)))?;

        let signed_txn = bincode::serialize(&signed_txn).map_err(|e| Status::internal(format!("Fail to serialize signed transaction due to error {:?}", e)))?;
        Ok(Response::new(SolanaSignResp{
            versioned_txn: signed_txn,
        } ))
    }
}
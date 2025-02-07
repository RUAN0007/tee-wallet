use tonic::{async_trait, Status};
use tonic_middleware::RequestInterceptor;
use tonic::body::BoxBody;
use tonic::codegen::http::Request;
use ed25519_dalek::{Verifier, VerifyingKey, SigningKey, Signer};
use tonic::metadata::{MetadataValue, Ascii};
use std::str::FromStr;

use crate::crypto;

pub mod header {
	pub static SIGNATURE: &str = "x-signature";
	pub static PUBKEY: &str = "x-pubkey";
	pub static CURVE: &str = "x-curve";
	pub static BODY_SHA256: &str = "x-body-sha256";

	pub static SECP256K1 : &str = "secp256k1";
	pub static ED25519 : &str = "ed25519";
}

#[derive(Clone)]
pub struct AuthInterceptor {}

#[async_trait]
impl RequestInterceptor for AuthInterceptor {
    async fn intercept(&self, req: Request<BoxBody>) -> Result<Request<BoxBody>, Status> {
		let signature = req.headers().get(header::SIGNATURE).ok_or(Status::unauthenticated("No signature"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid signature due to error {:?}", e)))?;
		let signature = hex::decode(signature).map_err(|e| Status::unauthenticated(format!("Fail to hex decode signature due to error {:?}", e)))?;

		let curve = req.headers().get(header::CURVE).ok_or(Status::unauthenticated("No curve"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid curve due to error {:?}", e)))?;

		let pk = req.headers().get(header::PUBKEY).ok_or(Status::unauthenticated("No address"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid address due to error {:?}", e)))?;

		let body_sha256 = req.headers().get(header::BODY_SHA256).ok_or(Status::unauthenticated("No body sha256"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid address due to error {:?}", e)))?;
		let body_sha256 = hex::decode(body_sha256).map_err(|e| Status::unauthenticated(format!("Fail to hex decode body sha256 due to error {:?}", e)))?;

		if curve != header::ED25519 {
			Status::unimplemented("Curve not supported");
		}

		let signature : [u8; 64] = signature.as_slice().try_into().map_err(|_| Status::unauthenticated("Invalid signature length"))?;
		let signature 		= ed25519_dalek::Signature::from_bytes(&signature);
		let pk = bs58::decode(pk).into_vec().map_err(|e| Status::unauthenticated(format!("Fail to decode base58 encoded public key due to error {:?}", e)))?;
		let pk : [u8;32] = pk.as_slice().try_into().map_err(|e| Status::unauthenticated(format!("Fail to convert base58 decoded public key to array due to error {:?}", e)))?;
		let pk = VerifyingKey::from_bytes(&pk).map_err(|e| Status::unauthenticated(format!("Fail to create ed25519 verifying key from bytes due to error {:?}", e)))?;

		pk.verify(&body_sha256, &signature).map_err(|e| Status::unauthenticated(format!("Fail to verify signature due to error {:?}", e)))?;

		Ok(req)
    }
}

pub fn validate_body_hash<T : prost::Message> (request : &tonic::Request<T>) -> Result<(), tonic::Status> {
    let body_sha256_in_header = request.metadata().get(header::BODY_SHA256).ok_or(Status::unauthenticated("No body sha256"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid body hash due to error {:?}", e)))?;
    let body_sha256 = hex::encode(crate::crypto::sha256(&request.get_ref().encode_to_vec()));
    if body_sha256_in_header != body_sha256 {
        return Err(Status::unauthenticated("Body hash mismatch"));
    }
    Ok(())
}

pub fn ed25519_pk_from_header<T : prost::Message> (request : &tonic::Request<T>) -> Result<VerifyingKey, tonic::Status> {
	let curve = request.metadata().get(header::CURVE).ok_or(Status::unauthenticated("No curve"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid curve due to error {:?}", e)))?;

	if curve != header::ED25519 {
		return Err(Status::unauthenticated("not ed25519 curive"));
	}

	let user_pk_in_header = request.metadata().get(header::PUBKEY).ok_or(Status::unauthenticated("No pub key"))?.to_str().map_err(|e| Status::unauthenticated(format!("Invalid pub key due to error {:?}", e)))?;
	let user_pk_vec = bs58::decode(user_pk_in_header).into_vec().map_err(|e| Status::unauthenticated(format!("Fail to decode base58 encoded public key due to error {:?}", e)))?;
	let user_pk : [u8;32] = user_pk_vec.as_slice().try_into().map_err(|_| Status::unauthenticated("Invalid public key length"))?;
	let user_pk = VerifyingKey::from_bytes(&user_pk).map_err(|e| Status::unauthenticated(format!("Fail to create ed25519 verifying key from bytes due to error {:?}", e)))?;
	Ok(user_pk)
}

pub fn addr_from_header<T : prost::Message> (request : &tonic::Request<T>) -> Result<String, tonic::Status> {
	let user_pk = ed25519_pk_from_header(request)?;
	Ok(crypto::ed25519_pk_to_addr(&user_pk))
}

pub fn gen_ed25519_signed_req<T : prost::Message> (request_body : T, sk : &SigningKey) -> Result<tonic::Request<T>, tonic::Status> {
	let body_sha256 = crypto::sha256(&request_body.encode_to_vec());
	let signature = sk.sign(&body_sha256);
	let pk = sk.verifying_key();
	let pk_bs58 = bs58::encode(pk.to_bytes()).into_string();

	let signature_hex = hex::encode(signature.to_bytes());
	let mut request = tonic::Request::new(request_body);
	let signature_header_val = MetadataValue::<Ascii>::from_str(&signature_hex).map_err(|e| Status::internal(format!("Fail to create metadata value from signature hex due to error {:?}", e)))?;
	let pubkey_header_val = MetadataValue::<Ascii>::from_str(&pk_bs58).map_err(|e| Status::internal(format!("Fail to create metadata value from public key bytes due to error {:?}", e)))?;
	let curve_header_val = MetadataValue::<Ascii>::from_str(header::ED25519).map_err(|e| Status::internal(format!("Fail to create metadata value from curve type due to error {:?}", e)))?;
	let body_sha245_val = MetadataValue::<Ascii>::from_str(&hex::encode(body_sha256)).map_err(|e| Status::internal(format!("Fail to create metadata value from body sha256 due to error {:?}", e)))?;

	request.metadata_mut().insert(header::SIGNATURE, signature_header_val);
	request.metadata_mut().insert(header::PUBKEY, pubkey_header_val);
	request.metadata_mut().insert(header::CURVE, curve_header_val);
	request.metadata_mut().insert(header::BODY_SHA256, body_sha245_val);

	Ok(request)
}
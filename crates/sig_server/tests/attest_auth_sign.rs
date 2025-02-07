#[cfg(test)]
mod tests {
	use rsa::RsaPublicKey;
    use sha2::digest::Key;
    use solana_sdk::signer::SeedDerivable;
    use trace::init_tracing;
    use utils::crypto::{encrypt, init_rsa_keypair};
    use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
	use tonic::transport::Server;
    use tonic::Request;
    use tokio::sync::OnceCell;
    use tonic::metadata::{MetadataValue, Ascii, Binary};
    use std::str::FromStr;
	use sig_server::service::attestation_svc::{
			attestation_server::AttestationServer, 
			AttestationHandler};
	use sig_server::service::test_svc::{
			test_server::TestServer, 
			TestHandler};
	use sig_server::service::authorization_svc::{
			authorization_server::AuthorizationServer, 
			AuthorizationHandler};
    use sig_server::service::SIG_HEADER;
    use attestation_doc_validation::attestation_doc::decode_attestation_document;
    use attestation_client::AttestationClient;
    use authorization_client::AuthorizationClient;

    use solana_sdk::transaction::VersionedTransaction;
    use solana_sdk::signature::Signer;
    use solana_sdk::signer::keypair::Keypair;
    use sig_server::config::SigServerConfig;
    use std::path::Path;
    use std::env;
    use std::fs;

    use prost::Message;
    use prost_types::Timestamp;

    use serde_json::Value;

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

        let authorization_service = AuthorizationServer::new(AuthorizationHandler::default());
        let auth_interceptor = utils::middleware::AuthInterceptor {};

        let signing_handler = SigningHandler::new(&cfg).expect("fail to create signing handler");
        let signing_service = SigningServer::new(signing_handler);

        Server::builder()
            .add_service(AttestationServer::new(AttestationHandler::default()))
            .add_service(InterceptorFor::new(authorization_service, auth_interceptor.clone()))
            .add_service(InterceptorFor::new(signing_service, auth_interceptor.clone()))
            .serve_with_incoming(stream)
            .await
            .unwrap();
        });
	}

	pub fn must_load_keypair() -> Keypair {
		// Get the path from the environment variable
		let key_path = env::var("SOLANA_KEY_PATH").expect("must set SOLANA_KEY_PATH");
		
		// Read the private key file
		let key_data = fs::read_to_string(Path::new(&key_path)).expect("fail to read from key_path");
		
		// Parse the JSON data
		let json: Value = serde_json::from_str(&key_data).unwrap();
		
		// Convert the JSON array to a Vec<u8>
		let key_bytes: Vec<u8> = json.as_array().unwrap()
			.iter()
			.map(|v| v.as_u64().unwrap() as u8)
			.collect::<Vec<u8>>();
		
		// Create the keypair from the bytes
		Keypair::from_bytes(&key_bytes).unwrap()
	}

    #[tokio::test]
    async fn attest_auth_sign() {

        let cfg = SigServerConfig::load("config/").unwrap();
        let cfg : SigServerConfig = cfg.try_deserialize().unwrap();
        let _ = init_tracing(cfg.trace.clone());

        SERVER.get_or_init(start_server).await;

        // 1. Parse attestation document to retrieve the TEE public key
        let url  = format!("http://{}:{}", HOST, PORT);
        let mut attestation_cli = AttestationClient::connect(url.clone()).await.unwrap();
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

        // 2. Encrypt the user private key with the TEE public key, and upload to TEE to authorize. 
        // let key_pair = must_load_keypair();

        // a random private key only for testing. 
        let random_sk = hex::decode(utils::TEST_ED25519_SK_HEX).unwrap();

        let key_pair = Keypair::from_seed(&random_sk).unwrap();
        tracing::info!("bs58 encoded sk: {:?}", solana_sdk::bs58::encode(key_pair.pubkey()).into_string());

        let sk_bytes = key_pair.secret().to_bytes();
        let encrypted_sk = encrypt(&public_key, &sk_bytes).expect("fail to encrypt");
        tracing::debug!("encrypted_sk: {:?}", hex::encode(&encrypted_sk));

        let start_at = Timestamp {
            seconds: 1738800000, // 2025-02-06 00:00:00 GMT
            nanos: 0,
        };

        let end_at = Timestamp {
            seconds: 1738886400, // 2025-02-07 00:00:00 GMT
            nanos: 0,
        };
        let auth_req = AuthorizationReq {
            svc_type: ServiceType::CopyTrading as i32, // 1
            start_at : Some(start_at),
            end_at : Some(end_at),
            action: "".to_owned(),
            condition: "".to_owned(),
            sk_ciphertext: encrypted_sk, // a possible ciphertext, (due to padding, ciphertext is diff for each encryptions): 6f59dfc5d9d164aa7e848c49ab265b8c360fb142d579bd698a2d986d6307982b862136b9a724ad6ded7d51198879d5599ea78933d8c531dd3ceab3edb86bce59c719d919dc5461a6ffd64d98ae57d4916792156197fc6232cc660e66d390f43969be70abe957664e1a9e62005d9ffea078135205117fd7a08fa300d6ceba2017dbbf9c9d7b344443ecffb0cac2ad1814f2a2902e6e1802016db802c5ea8928e195b5fa1e893a0856c20e5791d88d872aaed310e5652fba63480617f79e3746a5b38240bcbbbd2b77f16c21e660cd8ca9e2d8cae738e337019b27b72c75755fe7806daefffb2bbc98bc923277d5fbfcdba08bf9897596f0c70bbb9e14b9a08032

            key_type: KeyType::Ed25519 as i32, // 0
        };
        let mut request = Request::new(auth_req);
        let auth_req_bytes = request.get_ref().encode_to_vec();
        tracing::debug!("auth_req_bytes_hex: {:?}", hex::encode(&auth_req_bytes));
        // the corresponding request encoding: 080112060880f78fbd061a0608809a95bd063280026f59dfc5d9d164aa7e848c49ab265b8c360fb142d579bd698a2d986d6307982b862136b9a724ad6ded7d51198879d5599ea78933d8c531dd3ceab3edb86bce59c719d919dc5461a6ffd64d98ae57d4916792156197fc6232cc660e66d390f43969be70abe957664e1a9e62005d9ffea078135205117fd7a08fa300d6ceba2017dbbf9c9d7b344443ecffb0cac2ad1814f2a2902e6e1802016db802c5ea8928e195b5fa1e893a0856c20e5791d88d872aaed310e5652fba63480617f79e3746a5b38240bcbbbd2b77f16c21e660cd8ca9e2d8cae738e337019b27b72c75755fe7806daefffb2bbc98bc923277d5fbfcdba08bf9897596f0c70bbb9e14b9a08032

        let signature : [u8;64] = key_pair.sign_message(&auth_req_bytes).try_into().unwrap();
        let req_signature_hex = hex::encode(&signature);
        tracing::debug!("auth_req_signature_hex: {:?}", req_signature_hex);
        // the corresponding signature bfbc39064be4139204698bed58e827a184120c29cd960cae60b6e04da8e86e9797d38cd4c05a2e18f35201793552c72e69bc28b9036ce8ca05a9f0f41d0d4207

        let mut authorization_cli = AuthorizationClient::connect(url.clone()).await.unwrap();
        request.metadata_mut().insert(SIG_HEADER, MetadataValue::<Ascii>::from_str(&req_signature_hex).unwrap());


		let response = authorization_cli.authorize(request).await;

        assert!(response.is_ok(), "response: {:?}", response);

        // 3. Send a sign request to the TEE

    }
}
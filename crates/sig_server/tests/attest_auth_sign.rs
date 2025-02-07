#[cfg(test)]
mod tests {
	use ed25519_dalek::SigningKey;
    use once_cell::sync::Lazy;
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
    use std::sync::RwLock;
	use sig_server::service::attestation_svc::{
			attestation_server::AttestationServer, 
			AttestationHandler};
	use sig_server::service::test_svc::{
			test_server::TestServer, 
			TestHandler};
	use sig_server::service::authorization_svc::{
			authorization_server::AuthorizationServer, 
			AuthorizationHandler};
	use sig_server::service::signing_svc::{
			signing_server::SigningServer, 
			SigningHandler};
    use sig_server::service::SIG_HEADER;
    use attestation_doc_validation::attestation_doc::decode_attestation_document;
    use attestation_client::AttestationClient;
    use authorization_client::AuthorizationClient;
    use tonic_middleware::InterceptorFor;

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
    tonic::include_proto!("signing");

    const HOST : &str = "127.0.0.1";
    const PORT : u16 = 50053; // must be diff between each test case

    static SERVER : OnceCell<()> = OnceCell::const_new();
    // static Vec<WorkerGuard> 
    static CONFIG : Lazy<RwLock<SigServerConfig>> = Lazy::new(|| {
        let current_dir = env::current_dir().unwrap();
        println!("Current working directory: {:?}", current_dir);


        let cfg = SigServerConfig::load("config/").unwrap();
        let cfg : SigServerConfig = cfg.try_deserialize().unwrap();

        RwLock::new(cfg)
    });

    async fn start_server() {
		let addr : String = format!("{}:{}", HOST, PORT);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        tokio::spawn( async move {
        let stream = tokio_stream::wrappers::TcpListenerStream::new(listener);

        let authorization_service = AuthorizationServer::new(AuthorizationHandler::default());
        let auth_interceptor = utils::middleware::AuthInterceptor {};

        let signing_handler = SigningHandler::new(&CONFIG.read().unwrap()).expect("fail to create signing handler");
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
        let _ = init_tracing(CONFIG.read().unwrap().trace.clone());

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
        let user_sk_pair = Keypair::new();
        tracing::debug!("bs58 encoded pk: {:?}", solana_sdk::bs58::encode(user_sk_pair.pubkey()).into_string());
        // example output: J9yNMaR2zpkAGNK6xg3zLtV8sxB1EWXrYbC6JwhYx6nv

        let user_sk_bytes = user_sk_pair.secret().to_bytes();
        let user_sk_ciphertext = encrypt(&public_key, &user_sk_bytes).expect("fail to encrypt");
        tracing::debug!("sk_ciphertext: {:?}", hex::encode(&user_sk_ciphertext));

        // note: the ciphertext is different for each encryption, due to padding.
        // the corresponding ciphertext: 465464e59b2ea8b417cb6eb539c7aa24faa30feae432be3280df56b94f54678350931d97f61b13a36404f94a60cd11fab1af03e6fef416b2c2ad00344ecf6d8c44215306c159bc63500851db602b24876f52be9e62d08345ccc0ccb7876426e0b45c9282a41d38d06ab4a3a55a8cde65f816eff4719323bc93244c1c7e2e8adaceac9a9d095ece7996ce4873769da3266a3fc3463815b4da0f716cf8ad83366451bc227998e9a4d2bd5b06033452d78c575ad0f225dac94938085901431c682a178ba6710f37c26c0829ecf5ad8fbd455ab8605d54226ae7509dbadcece22aa4959bbace0666ad686e78d20763c8d385f5cae088114bf80dfc55692c0632cfc5

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
            sk_ciphertext: user_sk_ciphertext, // a possible ciphertext, (due to padding, ciphertext is diff for each encryptions): 

            key_type: KeyType::Ed25519 as i32, // 0
        };

        tracing::debug!("auth_req: {:?}", hex::encode(&auth_req.encode_to_vec()));
        // the corresponding hex encoded auth_req: 080112060880f78fbd061a0608809a95bd06328002465464e59b2ea8b417cb6eb539c7aa24faa30feae432be3280df56b94f54678350931d97f61b13a36404f94a60cd11fab1af03e6fef416b2c2ad00344ecf6d8c44215306c159bc63500851db602b24876f52be9e62d08345ccc0ccb7876426e0b45c9282a41d38d06ab4a3a55a8cde65f816eff4719323bc93244c1c7e2e8adaceac9a9d095ece7996ce4873769da3266a3fc3463815b4da0f716cf8ad83366451bc227998e9a4d2bd5b06033452d78c575ad0f225dac94938085901431c682a178ba6710f37c26c0829ecf5ad8fbd455ab8605d54226ae7509dbadcece22aa4959bbace0666ad686e78d20763c8d385f5cae088114bf80dfc55692c0632cfc5

        let user_signing_key = SigningKey::from_bytes(&user_sk_bytes);
        let request = utils::middleware::gen_ed25519_signed_req(auth_req, &user_signing_key).unwrap();
        tracing::debug!("request: {:?}", request);
        // the corresponding header: {"x-signature": "1ec6aee144ffbeb8aa54e526c85d3a15ee4e01bd8de2d43d9298932a90ee3797366f1d85b9a2baa71255ad2f9e170a76219ce762ad3be5532aa58c4df666ec07", "x-pubkey": "J9yNMaR2zpkAGNK6xg3zLtV8sxB1EWXrYbC6JwhYx6nv", "x-curve": "ed25519", "x-body-sha256": "e5e34dc33cda69fdc411c6685a6f153c26f41768f36137e47f040ac4483ba900"}

        let mut authorization_cli = AuthorizationClient::connect(url).await.unwrap();
		let response = authorization_cli.authorize(request).await;
        assert!(response.is_ok(), "response: {:?}", response);
        let auth_id = response.unwrap().into_inner().id;

        // 3. get auth record
        let get_req = GetAuthRecordsReq::default();
        let request = utils::middleware::gen_ed25519_signed_req(get_req, &user_signing_key).unwrap();
        let response = authorization_cli.get_authorization_records(request).await;
        assert!(response.is_ok(), "response: {:?}", response);
        let response = response.unwrap();
        assert_eq!(1, response.get_ref().records.len());
        assert_eq!(auth_id, response.get_ref().records[0].id);

        // 4. use DEX aggregator to get a unsigned transaction

    }
}
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::rngs::OsRng;
use rand::{rngs::StdRng, SeedableRng};
use std::error::Error;
use sha2::{Sha256, Digest};


pub fn init_rsa_keypair_with_seed(seed: [u8; 32]) -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = StdRng::from_seed(seed);
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn init_rsa_keypair() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);
    (private_key, public_key)
}

pub fn encrypt(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|e| e.into())
}

pub fn decrypt(private_key: &RsaPrivateKey, encrypted_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    private_key.decrypt(Pkcs1v15Encrypt, encrypted_data)
        .map_err(|e| e.into())
}

pub fn ed25519_pk_to_addr(pk: &ed25519_dalek::VerifyingKey) -> String {
    let addr = bs58::encode(pk.as_bytes()).into_string();
    addr
}


// pub fn secp256k1_pk_to_addr(pk: &secp256k1::PublicKey) -> String {
//     let serialized_pk = pk.serialize_uncompressed();
//     let hash = Keccak256::digest(&serialized_pk[1..]); // Skip the first byte (0x04)
//     let addr = &hash[12..]; // Take the last 20 bytes
//     format!("0x{}", hex::encode(addr))
// }

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
	use pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey};
    use rsa::traits::PublicKeyParts;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use serde_bytes::ByteBuf;
	use std::panic;

    #[test]
    fn test_rsa_keypair_generation() {
        let (private_key, public_key) = init_rsa_keypair();
        assert!(private_key.n().bits() == 2048);
        assert!(public_key.n().bits() == 2048);
    }

    #[test]
    fn test_rsa_encryption_decryption() {
        let (private_key, pk) = init_rsa_keypair();
        let bf = ByteBuf::from(pk.to_pkcs1_der().unwrap().as_bytes());
        let public_key = RsaPublicKey::from_pkcs1_der(&bf).expect("fail for pkcs der");

        let data = b"hello world";
        let encrypted_data = encrypt(&public_key, data).unwrap();
        let decrypted_data = decrypt(&private_key, &encrypted_data).unwrap();
        assert_eq!(data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_rsa_encryption_with_invalid_key() {
        let (private_key, _) = init_rsa_keypair();
        let (_, public_key) = init_rsa_keypair(); // Generate a different key pair
        let data = b"hello world";
        let encrypted_data = encrypt(&public_key, data).unwrap();
        let result = panic::catch_unwind(|| {
            let decrypted_data = decrypt(&private_key, &encrypted_data).unwrap(); // this step may panic. 
            assert_ne!(data.to_vec(), decrypted_data);
        });
		assert!(result.is_err(), "Decryption panicked");
    }


    #[test]
    fn test_rsa_sk() {
        let (private_key, pk) = init_rsa_keypair();
        let doc = private_key.to_pkcs1_der().unwrap();
        let sk_bytes = doc.as_bytes();
        println!("sk_bytes: {:?}", hex::encode(sk_bytes));

        let sk = RsaPrivateKey::from_pkcs1_der(sk_bytes).unwrap();
        let data = b"hello world";
        let encrypted_data = encrypt(&pk, data).unwrap();
        let decrypted_data = decrypt(&sk, &encrypted_data).unwrap();
        assert_eq!(data.to_vec(), decrypted_data);

    }
}

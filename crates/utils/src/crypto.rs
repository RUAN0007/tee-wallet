use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::rngs::OsRng;
use rand::{rngs::StdRng, SeedableRng};

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

use std::error::Error;

pub fn encrypt(public_key: &RsaPublicKey, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut rng = OsRng;
    public_key.encrypt(&mut rng, Pkcs1v15Encrypt, data)
        .map_err(|e| e.into())
}

pub fn decrypt(private_key: &RsaPrivateKey, encrypted_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    private_key.decrypt(Pkcs1v15Encrypt, encrypted_data)
        .map_err(|e| e.into())
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

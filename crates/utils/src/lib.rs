pub mod crypto;

use prost_types::Timestamp;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn current_protobuf_timestamp() -> Timestamp {
    let duration_since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    
    Timestamp {
        seconds: duration_since_epoch.as_secs() as i64,
        nanos: duration_since_epoch.subsec_nanos() as i32,
    }
}

pub static TEST_ED25519_SK_HEX : &str = "77162855b21a514f2cbabca428e647152f6129a2335557fbb1a921acc773f369"; // a random generated sk for testing purpose. The corresponding base58 encoded pk is: C7JsiaoVK87xAZXLrhoFW8pu2XwweDB8cJHGbxyW2dCT



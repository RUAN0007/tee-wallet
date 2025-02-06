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
use std::time::SystemTime;
use std::hash::{Hash, Hasher};
use std::hash::DefaultHasher;
use std::collections::{HashMap, BTreeMap};
use std::sync::RwLock;
use once_cell::sync::Lazy;
use crate::errors::SigServerError;
use crate::service::authorization_svc::Principal;
use crate::service::authorization_svc::KeyType;

#[derive(Hash, Clone, Debug, PartialEq)]
pub struct AuthRecord {
	pub addr: String,
	pub principal: Principal,
	pub start_at : SystemTime,	
	pub end_at : SystemTime,
	pub condition : String,
	pub action: String,
	pub sk: Vec<u8>,
	pub key_type: KeyType,
}

type AuthID = u64;

impl AuthRecord {
	pub fn id(&self) -> AuthID {
		let mut hasher = DefaultHasher::new(); // Create a new hasher
		self.hash(&mut hasher); // Hash the struct
		hasher.finish()
	}

}

pub static AUTH_REGISTRY: Lazy<RwLock<AuthRegistry>> = Lazy::new(|| RwLock::new(AuthRegistry::new()));

pub struct AuthRegistry {
	records : HashMap<AuthID, AuthRecord>,
	user_records_by_end_at : HashMap<String, BTreeMap<SystemTime, AuthID>>
}

impl AuthRegistry {
	pub fn new() -> Self {
		Self {
			records : HashMap::new(),
			user_records_by_end_at : HashMap::new()
		}
	}

	pub fn add(&mut self, record: AuthRecord) -> Result<AuthID, SigServerError> {
		let id = record.id();
		self.records.insert(id, record.clone());
		self.user_records_by_end_at.entry(record.addr.clone()).or_insert(BTreeMap::new()).insert(record.end_at, id);
		Ok(id)
	}

	pub fn search(&self, addr : &str, principal : Principal, _condition : &str, _action : &str) -> Option<AuthRecord> {
		let now = SystemTime::now();
		self.user_records_by_end_at.get(addr).and_then(|records| {
			records.range(now..).next().and_then(|(_, id)| {
				self.records.get(id).cloned()
			})
		})
	}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn create_test_record(addr: &str, principal: Principal, start_at: SystemTime, end_at: SystemTime) -> AuthRecord {
        AuthRecord {
            principal,
            start_at,
            end_at,
            condition: String::from("test_condition"),
            action: String::from("test_action"),
            sk: vec![1, 2, 3, 4],
            key_type: KeyType::Ed25519,
            addr: addr.to_string(),
        }
    }

    #[test]
    fn test_new() {
        let registry = AuthRegistry::new();
        assert!(registry.records.is_empty());
        assert!(registry.user_records_by_end_at.is_empty());
    }

    #[test]
    fn test_add() {
        let mut registry = AuthRegistry::new();
        let principal = Principal::LimitOrder;
        let start_at = SystemTime::now();
        let end_at = start_at + Duration::from_secs(3600);
        let record = create_test_record("test_addr", principal, start_at, end_at);

        let id = registry.add(record.clone()).unwrap();
        assert_eq!(registry.records.len(), 1);
        assert_eq!(registry.user_records_by_end_at.len(), 1);
        assert_eq!(registry.records.get(&id).unwrap(), &record);
    }

    #[test]
    fn test_search() {
        let mut registry = AuthRegistry::new();
        let principal = Principal::LimitOrder;
        let start_at = SystemTime::now();
        let end_at = start_at + Duration::from_secs(3600);
        let record = create_test_record("test_addr", principal, start_at, end_at);

        registry.add(record.clone());
        let result = registry.search("test_addr", principal, "test_condition", "test_action");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), record);
    }

    #[test]
    fn test_search_no_result() {
        let registry = AuthRegistry::new();
        let principal = Principal::LimitOrder;
        let result = registry.search("non_existent_addr", principal, "test_condition", "test_action");
        assert!(result.is_none());
    }
}
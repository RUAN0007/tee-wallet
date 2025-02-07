use std::time::SystemTime;
use std::hash::{Hash, Hasher};
use std::hash::DefaultHasher;
use std::collections::{HashMap, BTreeMap};
use std::sync::RwLock;
use once_cell::sync::Lazy;
use solana_sdk::signer::SignerError;
use crate::errors::SigServerError;
use crate::service::authorization_svc::ServiceType;
use crate::service::authorization_svc::KeyType;
use crate::service::authorization_svc::AuthorizationRecord;

#[derive(Hash, Clone, Debug, PartialEq)]
pub struct AuthRecord {
	pub addr: String,
	pub svc_type: ServiceType,
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

impl From<AuthRecord> for AuthorizationRecord {
    fn from(auth_record: AuthRecord) -> Self {
        AuthorizationRecord {
            id : auth_record.id(),
            svc_type: auth_record.svc_type.into(),
            start_at: Some(auth_record.start_at.into()),
            end_at: Some(auth_record.end_at.into()),
            condition: auth_record.condition,
            action: auth_record.action,
        }
    }
}

pub static AUTH_REGISTRY: Lazy<RwLock<AuthRegistry>> = Lazy::new(|| RwLock::new(AuthRegistry::new()));

pub struct AuthRegistry {
	records : HashMap<AuthID, AuthRecord>,
	user_records_by_end_at : HashMap<String, BTreeMap<SystemTime, AuthID>>
}

pub struct SearchParams {
    pub addr : String,
    pub after : SystemTime,
    pub before : SystemTime, 
    pub svc_type : ServiceType,
    pub condition : String,
    pub action : String,

    pub page_num : u32,
    pub page_size : u32,
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

	pub fn search(&self, addr : &str, svc_type : ServiceType, _condition : &str, _action : &str) -> Option<AuthRecord> {
		let now = SystemTime::now();
		self.user_records_by_end_at.get(addr).and_then(|records| {
			records.range(now..).next().and_then(|(_, id)| {
				self.records.get(id).cloned()
			})
		})
	}

    pub fn search_by_params(&self, params: &SearchParams) -> Result<Vec<AuthRecord>, SigServerError> {
        let mut result = Vec::new();
        if let Some(records) = self.user_records_by_end_at.get(&params.addr) {
            for (_end_at, id) in records.range(params.after..params.before) {
                if let Some(record) = self.records.get(id) {
                    result.push(record.clone());
                }
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    fn create_test_record(addr: &str, svc_type: ServiceType, start_at: SystemTime, end_at: SystemTime) -> AuthRecord {
        AuthRecord {
            svc_type,
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
        let svc_type = ServiceType::LimitOrder;
        let start_at = SystemTime::now();
        let end_at = start_at + Duration::from_secs(3600);
        let record = create_test_record("test_addr", svc_type, start_at, end_at);

        let id = registry.add(record.clone()).unwrap();
        assert_eq!(registry.records.len(), 1);
        assert_eq!(registry.user_records_by_end_at.len(), 1);
        assert_eq!(registry.records.get(&id).unwrap(), &record);
    }

    #[test]
    fn test_search() {
        let mut registry = AuthRegistry::new();
        let svc_type = ServiceType::LimitOrder;
        let start_at = SystemTime::now();
        let end_at = start_at + Duration::from_secs(3600);
        let record = create_test_record("test_addr", svc_type, start_at, end_at);

        registry.add(record.clone());
        let result = registry.search("test_addr", svc_type, "test_condition", "test_action");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), record);
    }

    #[test]
    fn test_search_no_result() {
        let registry = AuthRegistry::new();
        let svc_type = ServiceType::LimitOrder;
        let result = registry.search("non_existent_addr", svc_type, "test_condition", "test_action");
        assert!(result.is_none());
    }
}
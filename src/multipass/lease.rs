use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct LeaseRequest {
    pub anchor_id: String,
    pub mobile_pk: Vec<u8>,
    pub tier: u8,
    pub expiration: u64,
}

// Placeholder for Lease/Delegation Token utilities
pub struct MultipassUtils;

impl MultipassUtils {
    pub fn calculate_expiration(duration_seconds: u64) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + duration_seconds
    }
}

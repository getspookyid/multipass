// Add-on Miner Module for ARM-based Hardware (Brume 2)
// ========================================================
// Implements k-anonymity buffer and ε-differential privacy for macro data

use parking_lot::RwLock;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::Db;
use statrs::distribution::{Laplace, ContinuousCDF};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

// K-anonymity minimum threshold
const K_ANONYMITY_THRESHOLD: usize = 15;

// Default epsilon for differential privacy
const DEFAULT_EPSILON: f64 = 1.0;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroDataPoint {
    pub category: String,
    pub value: f64,
    pub timestamp: u64,
    pub identity_hash: String,  // Blinded identity hash
}

#[derive(Debug, Clone)]
pub struct AnonymityBuffer {
    pub category: String,
    pub data_points: VecDeque<MacroDataPoint>,
    pub unique_identities: HashMap<String, usize>,
}

impl AnonymityBuffer {
    fn new(category: String) -> Self {
        Self {
            category,
            data_points: VecDeque::new(),
            unique_identities: HashMap::new(),
        }
    }

    fn add_data_point(&mut self, point: MacroDataPoint) {
        *self.unique_identities.entry(point.identity_hash.clone()).or_insert(0) += 1;
        self.data_points.push_back(point);
    }

    fn unique_count(&self) -> usize {
        self.unique_identities.len()
    }

    pub fn check_attribute_safety(attributes: &[String]) -> bool {
        // Attribute Correlation Defense:
        // Reject attempts to disclose too many attributes at once to prevent fingerprinting.
        // A user revealing Age + Zip + Gender + Income is likely unique.
        // Limit to 3 concurrent attributes.
        if attributes.len() > 3 {
             return false;
        }
        true
    }

    fn is_ready(&self) -> bool {
        self.unique_count() >= K_ANONYMITY_THRESHOLD
    }

    fn flush(&mut self) -> Vec<MacroDataPoint> {
        let result: Vec<MacroDataPoint> = self.data_points.drain(..).collect();
        self.unique_identities.clear();
        result
    }
}

// ============================================================================
// Miner Engine
// ============================================================================

pub struct MinerEngine {
    buffers: Arc<RwLock<HashMap<String, AnonymityBuffer>>>,
    vault: Db,
    epsilon: f64,
}

impl MinerEngine {
    pub fn new(vault_path: &str, epsilon: f64) -> Result<Self, String> {
        let vault = sled::open(vault_path).map_err(|e| format!("Failed to open vault: {}", e))?;

        Ok(Self {
            buffers: Arc::new(RwLock::new(HashMap::new())),
            vault,
            epsilon,
        })
    }

    /// Submit a macro data point to the k-anonymity buffer
    pub fn submit_macro_data(
        &self,
        category: String,
        value: f64,
        identity: &[u8],
    ) -> Result<Option<Vec<MacroDataPoint>>, String> {
        // Hash the identity to prevent raw storage
        let identity_hash = Self::hash_identity(identity);

        let data_point = MacroDataPoint {
            category: category.clone(),
            value,
            timestamp: Self::current_timestamp(),
            identity_hash,
        };

        let mut buffers = self.buffers.write();

        // Get or create buffer for this category
        let buffer = buffers
            .entry(category.clone())
            .or_insert_with(|| AnonymityBuffer::new(category.clone()));

        buffer.add_data_point(data_point);

        // Check if we have k-anonymity
        // Dynamic Threshold: If it's a "rare" category, raise the bar
        let threshold = Self::get_dynamic_threshold(category.clone());
        
        if buffer.unique_count() >= threshold {
            let ready_data = buffer.flush();

            // Apply differential privacy and store in vault
            let anonymized_data = self.apply_differential_privacy(ready_data)?;
            self.store_in_vault(&anonymized_data)?;
            
            // Audit Log: Record epsilon usage
            self.log_noise_audit("SUBMIT_BATCH", self.epsilon);

            Ok(Some(anonymized_data))
        } else {
            Ok(None)
        }
    }
    
    /// Calculate dynamic K-threshold based on category
    /// Mitigates N=16 attack by requiring larger crowds for sensitive/rare categories
    fn get_dynamic_threshold(category: String) -> usize {
        let base = K_ANONYMITY_THRESHOLD;
        match category.as_str() {
            "HIV_STATUS" | "POLITICAL_AFFILIATION" => base * 2, // Require 30
            "AGE_BRACKET" | "ZIP_CODE" => base + 5, // Require 20
            _ => base // 15
        }
    }
    
    fn log_noise_audit(&self, action: &str, cost: f64) {
        // In a real system, this goes to an append-only log file or blockchain
        println!("[NOISE AUDIT] Action: {}, Cost: ε{}, Timestamp: {}", 
            action, cost, Self::current_timestamp());
    }

    /// Apply Laplace noise for ε-differential privacy
    fn apply_differential_privacy(
        &self,
        data_points: Vec<MacroDataPoint>,
    ) -> Result<Vec<MacroDataPoint>, String> {
        let mut rng = rand::thread_rng();
        let laplace = Laplace::new(0.0, 1.0 / self.epsilon)
            .map_err(|e| format!("Failed to create Laplace distribution: {}", e))?;

        let noisy_data: Vec<MacroDataPoint> = data_points
            .into_iter()
            .map(|mut point| {
                // Add Laplace noise to the value using inverse CDF method
                let u: f64 = rng.gen_range(0.0..1.0);
                let noise = laplace.inverse_cdf(u);
                point.value += noise;

                // Remove exact timestamp precision (round to hour)
                point.timestamp = (point.timestamp / 3600) * 3600;

                // CRITICAL: Strip identity hash to ensure k-anonymity
                // The identity was only needed for the buffer threshold
                point.identity_hash = String::new();

                point
            })
            .collect();

        Ok(noisy_data)
    }

    /// Store anonymized data in sled vault
    fn store_in_vault(&self, data: &[MacroDataPoint]) -> Result<(), String> {
        for point in data {
            let key = format!("{}:{}", point.category, point.timestamp);
            let value = serde_json::to_vec(point)
                .map_err(|e| format!("Failed to serialize data point: {}", e))?;

            self.vault
                .insert(key.as_bytes(), value)
                .map_err(|e| format!("Failed to insert into vault: {}", e))?;
        }

        self.vault
            .flush()
            .map_err(|e| format!("Failed to flush vault: {}", e))?;

        Ok(())
    }

    /// Hash identity to prevent raw storage
    fn hash_identity(identity: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(identity);
        hex::encode(hasher.finalize())
    }

    /// Get current UNIX timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    /// Get buffer statistics
    pub fn get_buffer_stats(&self) -> HashMap<String, usize> {
        let buffers = self.buffers.read();
        buffers
            .iter()
            .map(|(category, buffer)| (category.clone(), buffer.unique_count()))
            .collect()
    }

    pub fn check_attribute_safety(&self, attributes: &[String]) -> bool {
        // Attribute Correlation Defense:
        // Reject attempts to disclose too many attributes at once to prevent fingerprinting.
        // A user revealing Age + Zip + Gender + Income is likely unique.
        // Limit to 3 concurrent attributes.
        // Note: 'attributes' here refers to the list of disclosed messages/claims.
        if attributes.len() > 3 {
             return false;
        }
        true
    }

    /// Retrieve anonymized data from vault
    pub fn query_vault(
        &self,
        category: &str,
        start_timestamp: u64,
        end_timestamp: u64,
    ) -> Result<Vec<MacroDataPoint>, String> {
        let mut results = Vec::new();

        for result in self.vault.iter() {
            let (key, value) = result.map_err(|e| format!("Vault iteration error: {}", e))?;

            let key_str = String::from_utf8_lossy(&key);

            // Parse key format: "category:timestamp"
            if let Some(colon_pos) = key_str.find(':') {
                let key_category = &key_str[..colon_pos];
                let key_timestamp: u64 = key_str[colon_pos + 1..]
                    .parse()
                    .unwrap_or(0);

                if key_category == category
                    && key_timestamp >= start_timestamp
                    && key_timestamp <= end_timestamp
                {
                    let point: MacroDataPoint = serde_json::from_slice(&value)
                        .map_err(|e| format!("Failed to deserialize data point: {}", e))?;
                    results.push(point);
                }
            }
        }

        Ok(results)
    }

    // ========================================================================
    // REVOCATION REGISTRY (Chain 1)
    // ========================================================================
    
    /// Check if a linkage tag is revoked
    pub fn is_tag_revoked(&self, linkage_tag: &str) -> Result<bool, String> {
        let tree = self.vault.open_tree("revocations").map_err(|e| e.to_string())?;
        match tree.contains_key(linkage_tag) {
            Ok(found) => Ok(found),
            Err(e) => Err(format!("Revocation check error: {}", e))
        }
    }

    /// Revoke a linkage tag (Admin function)
    pub fn revoke_tag(&self, linkage_tag: &str, reason: &str) -> Result<(), String> {
        let tree = self.vault.open_tree("revocations").map_err(|e| e.to_string())?;
        
        let meta = serde_json::json!({
            "revoked_at": Self::current_timestamp(),
            "reason": reason
        });
        
        tree.insert(linkage_tag, meta.to_string().as_bytes())
            .map_err(|e| format!("Failed to revoke tag: {}", e))?;
            
        Ok(())
    }

    // ========================================================================
    // SESSION PERSISTENCE (Phase 3.2)
    // ========================================================================

    pub fn store_session(&self, session_id: &str, session_json: &str) -> Result<(), String> {
        let tree = self.vault.open_tree("sessions").map_err(|e| e.to_string())?;
        tree.insert(session_id, session_json.as_bytes())
            .map_err(|e| format!("Failed to store session: {}", e))?;
        Ok(())
    }

    pub fn delete_session(&self, session_id: &str) -> Result<(), String> {
        let tree = self.vault.open_tree("sessions").map_err(|e| e.to_string())?;
        tree.remove(session_id).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn all_sessions(&self) -> Result<HashMap<String, String>, String> {
        let tree = self.vault.open_tree("sessions").map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        for result in tree.iter() {
            let (k, v) = result.map_err(|e| e.to_string())?;
            map.insert(String::from_utf8_lossy(&k).to_string(), String::from_utf8_lossy(&v).to_string());
        }
        Ok(map)
    }

    // ========================================================================
    // DEVICE KEY PERSISTENCE (Phase 8)
    // ========================================================================

    pub fn store_device_key(&self, device_id: &str, key_bytes: &[u8]) -> Result<(), String> {
        let tree = self.vault.open_tree("device_keys").map_err(|e| e.to_string())?;
        tree.insert(device_id, key_bytes)
            .map_err(|e| format!("Failed to store device key: {}", e))?;
        Ok(())
    }

    pub fn get_device_key(&self, device_id: &str) -> Result<Option<Vec<u8>>, String> {
        let tree = self.vault.open_tree("device_keys").map_err(|e| e.to_string())?;
        match tree.get(device_id) {
            Ok(Some(ivec)) => Ok(Some(ivec.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Device key retrieval error: {}", e)),
        }
    }

    pub fn all_device_keys(&self) -> Result<HashMap<String, Vec<u8>>, String> {
        let tree = self.vault.open_tree("device_keys").map_err(|e| e.to_string())?;
        let mut map = HashMap::new();
        for result in tree.iter() {
            let (k, v) = result.map_err(|e| e.to_string())?;
            map.insert(String::from_utf8_lossy(&k).to_string(), v.to_vec());
        }
        Ok(map)
    }

    // ========================================================================
    // INVITE SYSTEM (Phase 10)
    // ========================================================================

    pub fn store_invite(&self, code: &str, data: &[u8]) -> Result<(), String> {
        let tree = self.vault.open_tree("invites").map_err(|e| e.to_string())?;
        tree.insert(code, data)
            .map_err(|e| format!("Failed to store invite: {}", e))?;
        Ok(())
    }

    pub fn get_invite(&self, code: &str) -> Result<Option<Vec<u8>>, String> {
        let tree = self.vault.open_tree("invites").map_err(|e| e.to_string())?;
        match tree.get(code) {
            Ok(Some(ivec)) => Ok(Some(ivec.to_vec())),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Invite retrieval error: {}", e)),
        }
    }

    pub fn delete_invite(&self, code: &str) -> Result<(), String> {
        let tree = self.vault.open_tree("invites").map_err(|e| e.to_string())?;
        tree.remove(code).map_err(|e| e.to_string())?;
        Ok(())
    }
}

// ============================================================================
// Multipass Household Isolation
// ============================================================================

/// Generate non-correlatable blinding factor for a Multipass ID
/// Even with the same Hardware Anchor, different Multipass IDs produce
/// mathematically unlinkable ZKPs
pub fn generate_multipass_blinding_factor(
    multipass_id: &[u8],
    hardware_anchor: &[u8],
    session_counter: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Hash multipass_id separately
    hasher.update(b"MULTIPASS_BLINDING:");
    hasher.update(multipass_id);

    // XOR with hardware anchor (non-reversible)
    hasher.update(b"|ANCHOR:");
    hasher.update(hardware_anchor);

    // Add session counter for forward secrecy
    hasher.update(b"|SESSION:");
    hasher.update(&session_counter.to_le_bytes());

    // Add entropy from timestamp
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    hasher.update(&timestamp.to_le_bytes());

    let hash = hasher.finalize();

    let mut result = [0u8; 32];
    result.copy_from_slice(&hash[..32]);
    result
}

/// Verify that two blinding factors are non-correlatable
/// Returns true if blinding factors appear independent
pub fn verify_non_correlatability(
    blinding_factor_1: &[u8; 32],
    blinding_factor_2: &[u8; 32],
) -> bool {
    // Hamming distance should be close to 128 bits (50% of 256 bits)
    let hamming_distance: usize = blinding_factor_1
        .iter()
        .zip(blinding_factor_2.iter())
        .map(|(a, b)| (a ^ b).count_ones() as usize)
        .sum();

    // Should be between 100 and 156 bits different (near 50% ± 20%)
    hamming_distance >= 100 && hamming_distance <= 156
}

// ============================================================================
// FFI Exports for Go Integration
// ============================================================================

use std::os::raw::c_char;
use std::ffi::CStr;
use std::ptr;

static mut MINER_ENGINE: Option<MinerEngine> = None;

#[no_mangle]
pub extern "C" fn miner_init(
    vault_path: *const c_char,
    epsilon: f64,
) -> i32 {
    if vault_path.is_null() {
        return -1;
    }

    let result = std::panic::catch_unwind(|| {
        unsafe {
            let path_cstr = CStr::from_ptr(vault_path);
            let path_str = match path_cstr.to_str() {
                Ok(s) => s,
                Err(_) => return -1,
            };

            match MinerEngine::new(path_str, epsilon) {
                Ok(engine) => {
                    MINER_ENGINE = Some(engine);
                    0
                }
                Err(_) => -1,
            }
        }
    });

    result.unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn miner_submit_data(
    category: *const c_char,
    value: f64,
    identity: *const u8,
    identity_len: usize,
    ready_count: *mut usize,
) -> i32 {
    if category.is_null() || identity.is_null() || ready_count.is_null() {
        return -1;
    }

    let result = std::panic::catch_unwind(|| {
        unsafe {
            let engine = match MINER_ENGINE.as_ref() {
                Some(e) => e,
                None => return -1,
            };

            let category_cstr = CStr::from_ptr(category);
            let category_str = match category_cstr.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => return -1,
            };

            let identity_slice = std::slice::from_raw_parts(identity, identity_len);

            match engine.submit_macro_data(category_str, value, identity_slice) {
                Ok(Some(data)) => {
                    *ready_count = data.len();
                    0
                }
                Ok(None) => {
                    *ready_count = 0;
                    0
                }
                Err(_) => -1,
            }
        }
    });

    result.unwrap_or(-1)
}

#[no_mangle]
pub extern "C" fn miner_generate_blinding_factor(
    multipass_id: *const u8,
    multipass_id_len: usize,
    hardware_anchor: *const u8,
    hardware_anchor_len: usize,
    session_counter: u64,
    output: *mut u8,
) -> i32 {
    if multipass_id.is_null() || hardware_anchor.is_null() || output.is_null() {
        return -1;
    }

    let result = std::panic::catch_unwind(|| {
        unsafe {
            let multipass_slice = std::slice::from_raw_parts(multipass_id, multipass_id_len);
            let anchor_slice = std::slice::from_raw_parts(hardware_anchor, hardware_anchor_len);

            let blinding_factor = generate_multipass_blinding_factor(
                multipass_slice,
                anchor_slice,
                session_counter,
            );

            std::ptr::copy_nonoverlapping(blinding_factor.as_ptr(), output, 32);
            0
        }
    });

    result.unwrap_or(-1)
}

// Missing dependency - add hex crate
// Add to Cargo.toml: hex = "0.4"

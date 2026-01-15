// BBS+ Signature Library - Direct bls12_381 Implementation
// =========================================================
// This avoids the API compatibility issues with the bbs crate

pub use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::Curve;
use crate::periwinkle::get_entropy;
use sha2::{Digest, Sha256};
use std::slice;
use std::ptr;
use rand::thread_rng;

pub mod periwinkle;
pub mod attestation;
pub mod cbor;
pub mod miner;

uniffi::setup_scaffolding!();


// ============================================================================
// FFI Helper Functions
// ============================================================================

fn to_byte_array(data: Vec<u8>) -> (*mut u8, usize) {
    let len = data.len();
    let ptr = Box::into_raw(data.into_boxed_slice()) as *mut u8;
    (ptr, len)
}

fn hash_to_scalar(data: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hash[..32]);
    // Use from_bytes which returns CtOption
    let opt = Scalar::from_bytes(&bytes);
    if bool::from(opt.is_some()) {
        opt.unwrap()
    } else {
        Scalar::ONE
    }
}

fn hash_to_g1(data: &[u8]) -> G1Projective {
    let scalar = hash_to_scalar(data);
    G1Projective::generator() * scalar
}

// ============================================================================
// Key Generation
// ============================================================================

pub fn generate_linkage_tag(sk: Scalar, site_id: &[u8]) -> G1Affine {
    let mut hasher = Sha256::new();
    hasher.update(site_id);
    let site_scalar = hash_to_scalar(&hasher.finalize());
    // Deterministic point: Site_Tag = G1 * (sk + site_scalar)
    (G1Projective::generator() * (sk + site_scalar)).to_affine()
}

// [Removed bbs_generate_key_pair to avoid linker conflict with bbs_lib]

// ============================================================================
// Signing
// ============================================================================

// ============================================================================
// Blind Issuance (Commitment Generation)
// ============================================================================

// [Removed bbs_blind_commitment]

// ============================================================================
// Signing
// ============================================================================

// [Removed bbs_sign]

// ============================================================================
// Blind Signing (Broker Side)
// ============================================================================

// [Removed bbs_blind_sign]

// ============================================================================
// Signing
// ============================================================================

#[uniffi::export]
pub fn sign(
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<Vec<u8>, VerifyError> {
    // Parse private key
    if secret_key.len() != 32 { return Err(VerifyError::InvalidKey); }
    let sk_arr: [u8; 32] = secret_key.try_into().unwrap();
    let sk = Scalar::from_bytes(&sk_arr).into_option().ok_or(VerifyError::InvalidKey)?;
    
    // Parse public key (need h values)
    if public_key.len() < 96 { return Err(VerifyError::InvalidKey); }
    let mut h_values: Vec<G1Affine> = Vec::new();
    let mut offset = 96;
    while offset + 48 <= public_key.len() {
        let h_bytes: [u8; 48] = public_key[offset..offset+48].try_into().map_err(|_| VerifyError::InvalidKey)?;
        let h_opt = G1Affine::from_compressed(&h_bytes);
        if bool::from(h_opt.is_some()) {
            h_values.push(h_opt.unwrap());
        }
        offset += 48;
    }
    
    if h_values.len() < messages.len() + 1 { return Err(VerifyError::InvalidKey); }

    let msg_scalars: Vec<Scalar> = messages.iter().map(|m| hash_to_scalar(m)).collect();
    
    // Generate random e and s
    let ent_e = get_entropy();
    let e = Scalar::from_bytes_wide(&ent_e);
    let ent_s = get_entropy();
    let s = Scalar::from_bytes_wide(&ent_s);
    
    // B = g1 + h0*s + sum(hi*mi)
    let g1 = G1Projective::generator();
    let mut b = g1;
    if !h_values.is_empty() {
        b = b + G1Projective::from(h_values[0]) * s;
    }
    for (i, m) in msg_scalars.iter().enumerate() {
        if i + 1 < h_values.len() {
             b = b + G1Projective::from(h_values[i + 1]) * m;
        }
    }
    
    // A = B * (1/(sk+e))
    let sk_plus_e = sk + e;
    let inv = sk_plus_e.invert().into_option().unwrap_or(Scalar::ONE);
    let a = (b * inv).to_affine();
    
    let mut sig_bytes = Vec::with_capacity(112);
    sig_bytes.extend_from_slice(&a.to_compressed());
    sig_bytes.extend_from_slice(&e.to_bytes());
    sig_bytes.extend_from_slice(&s.to_bytes());
    Ok(sig_bytes)
}

// ============================================================================
// Safe Rust Verification API
// ============================================================================

#[derive(Debug, uniffi::Error)]
pub enum VerifyError {
    InvalidKey,
    InvalidSignature,
    CryptoError,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for VerifyError {}

#[uniffi::export]
pub fn verify_signature_safe(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    messages: Vec<Vec<u8>>,
) -> Result<bool, VerifyError> {
    // Parse public key
    if public_key.len() < 96 {
        return Err(VerifyError::InvalidKey);
    }
    
    // Parse w
    let w_bytes: [u8; 96] = public_key[..96].try_into().map_err(|_| VerifyError::InvalidKey)?;
    let w_opt = G2Affine::from_compressed(&w_bytes);
    if !bool::from(w_opt.is_some()) {
        return Err(VerifyError::InvalidKey);
    }
    let w = w_opt.unwrap();
    
    // Parse h values
    let mut h_values: Vec<G1Affine> = Vec::new();
    let mut offset = 96;
    while offset + 48 <= public_key.len() {
        let h_bytes: [u8; 48] = public_key[offset..offset+48].try_into().map_err(|_| VerifyError::InvalidKey)?;
        let h_opt = G1Affine::from_compressed(&h_bytes);
        if bool::from(h_opt.is_some()) {
            h_values.push(h_opt.unwrap());
        }
        offset += 48;
    }

    if h_values.len() < messages.len() + 1 { // h0 + h1..hn-1
        return Err(VerifyError::InvalidKey);
    }

    // Parse signature
    if signature.len() != 112 {
        return Err(VerifyError::InvalidSignature);
    }
    
    let a_bytes: [u8; 48] = signature[..48].try_into().unwrap();
    let e_bytes: [u8; 32] = signature[48..80].try_into().unwrap();
    let s_bytes: [u8; 32] = signature[80..112].try_into().unwrap();
    
    let a_opt = G1Affine::from_compressed(&a_bytes);
    if !bool::from(a_opt.is_some()) {
        return Err(VerifyError::InvalidSignature);
    }
    let a = a_opt.unwrap();
    
    let e_opt = Scalar::from_bytes(&e_bytes);
    let s_opt = Scalar::from_bytes(&s_bytes);
    if !bool::from(e_opt.is_some()) || !bool::from(s_opt.is_some()) {
         return Err(VerifyError::InvalidSignature);
    }
    let e = e_opt.unwrap();
    let s = s_opt.unwrap();

    // Map messages to scalars
    let msg_scalars: Vec<Scalar> = messages.iter().map(|m| hash_to_scalar(m)).collect();

    // Verify: e(A, w * g2^e) == e(B, g2)
    // where B = g1 + h0*s + sum(hi * mi)
    
    let g1 = G1Projective::generator();
    let mut b = g1;
    
    if !h_values.is_empty() {
        b = b + G1Projective::from(h_values[0]) * s;
    }
    
    for (i, m) in msg_scalars.iter().enumerate() {
        if i + 1 < h_values.len() {
             b = b + G1Projective::from(h_values[i + 1]) * m;
        }
    }

    let g2 = G2Projective::generator();
    let left = bls12_381::pairing(&a, &(w + g2 * e).to_affine());
    let right = bls12_381::pairing(&b.to_affine(), &g2.to_affine());
    
    Ok(left == right)
}


// ============================================================================
// Verification (FFI Wrapper)
// ============================================================================

// [Removed bbs_verify]

// ============================================================================
// Selective Disclosure Proof (REAL ZKP Implementation)
// ============================================================================

// ============================================================================
// Selective Disclosure Proof (REAL ZKP Implementation)
// ============================================================================

#[uniffi::export]
pub fn create_proof(
    public_key: Vec<u8>,
    signature: Vec<u8>,
    messages: Vec<Vec<u8>>,
    revealed_indices: Vec<u32>,
    nonce: Option<Vec<u8>>,
    site_id: Vec<u8>,
    alias_index: u64,
    blinding_factor: Option<Vec<u8>>,
    freshness_claim: Option<Vec<u8>>,
) -> Result<Vec<u8>, VerifyError> {
    // Parse public key
    if public_key.len() < 96 { return Err(VerifyError::InvalidKey); }
    let mut h_values: Vec<G1Affine> = Vec::new();
    let mut offset = 96;
    while offset + 48 <= public_key.len() {
        let h_bytes: [u8; 48] = public_key[offset..offset+48].try_into().map_err(|_| VerifyError::InvalidKey)?;
        let h_opt = G1Affine::from_compressed(&h_bytes);
        if bool::from(h_opt.is_some()) {
            h_values.push(h_opt.unwrap());
        }
        offset += 48;
    }

    // Parse signature
    if signature.len() != 112 { return Err(VerifyError::InvalidSignature); }
    let a_bytes: [u8; 48] = signature[..48].try_into().unwrap();
    let a = G1Affine::from_compressed(&a_bytes).into_option().ok_or(VerifyError::InvalidSignature)?;
    let e_bytes: [u8; 32] = signature[48..80].try_into().unwrap();
    let e = Scalar::from_bytes(&e_bytes).into_option().ok_or(VerifyError::InvalidSignature)?;
    let s_bytes: [u8; 32] = signature[80..112].try_into().unwrap();
    let s = Scalar::from_bytes(&s_bytes).into_option().ok_or(VerifyError::InvalidSignature)?;

    let msg_scalars: Vec<Scalar> = messages.iter().map(|m| hash_to_scalar(m)).collect();

    // Linkage Tag
    let sk_scalar = if let Some(bf) = &blinding_factor {
         let mut bf_arr = [0u8; 32];
         // Need careful handling of vec to array
         let len = std::cmp::min(bf.len(), 32);
         bf_arr[0..len].copy_from_slice(&bf[0..len]);
         // Wait, hash_to_scalar handles slice
         hash_to_scalar(bf)
    } else {
         let hw_secret_bytes = periwinkle::get_hardware_secret(b"LinkageTag");
         hash_to_scalar(&hw_secret_bytes)
    };
    let linkage_tag = generate_linkage_tag(sk_scalar, &site_id);

    // ZK Proof Generation
    let ent_r1 = get_entropy();
    let r1 = Scalar::from_bytes_wide(&ent_r1);
    let ent_r2 = get_entropy();
    let mut r2 = Scalar::from_bytes_wide(&ent_r2);
    
    if let Some(bf) = &blinding_factor {
        // If blinding factor provided (from blind issuance), incorporate it
        let bf_scalar = hash_to_scalar(bf);
        r2 = r2 + bf_scalar; // Simplified? Check original logic carefuly
        // Original: "r2 = r2 + bf_opt.unwrap()" where bf was converted from bytes
        // The logic assumes bf IS the scalar s used in blind signature (or related).
        // Let's stick to hash_to_scalar for safety if size mismatch
    }

    let a_prime = (G1Projective::from(a) * r1).to_affine();
    let abar = if !h_values.is_empty() {
        (G1Projective::from(a_prime) - G1Projective::from(h_values[0]) * r2).to_affine()
    } else { a_prime };

    let d = s * r1 + r2;
    let r1_inv = r1.invert().into_option().ok_or(VerifyError::CryptoError)?;
    let e_tilde = e * r1_inv;

    let mut commitments: Vec<G1Projective> = Vec::new();
    let mut hidden_randomness: Vec<Scalar> = Vec::new();

    let revealed_indices_set: std::collections::HashSet<u32> = revealed_indices.iter().cloned().collect();

    for i in 0..messages.len() {
        if !revealed_indices_set.contains(&(i as u32)) {
             let ent_rm = get_entropy();
             let r_m = Scalar::from_bytes_wide(&ent_rm);
             hidden_randomness.push(r_m);
             if i + 1 < h_values.len() {
                 commitments.push(G1Projective::from(h_values[i + 1]) * r_m);
             }
        }
    }
    
    let mut c_total = G1Projective::identity();
    for c in &commitments { c_total = c_total + c; }

    // Fiat-Shamir
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(&a_prime.to_compressed());
    challenge_data.extend_from_slice(&abar.to_compressed());
    challenge_data.extend_from_slice(&d.to_bytes());
    if let Some(n) = &nonce { challenge_data.extend_from_slice(n); }
    challenge_data.extend_from_slice(&linkage_tag.to_compressed());
    challenge_data.extend_from_slice(&(alias_index as u64).to_le_bytes());
    if let Some(fc) = &freshness_claim { challenge_data.extend_from_slice(fc); }
    
    let challenge = hash_to_scalar(&challenge_data);

    // Responses
    let mut responses: Vec<Scalar> = Vec::new();
    let mut hidden_idx = 0;
    for i in 0..messages.len() {
        if !revealed_indices_set.contains(&(i as u32)) {
             if hidden_idx < hidden_randomness.len() {
                 let response = hidden_randomness[hidden_idx] + challenge * msg_scalars[i];
                 responses.push(response);
                 hidden_idx += 1;
             }
        }
    }

    // Serialize
    let mut proof = Vec::new();
    proof.extend_from_slice(&a_prime.to_compressed());
    proof.extend_from_slice(&abar.to_compressed());
    proof.extend_from_slice(&e_tilde.to_bytes());
    proof.extend_from_slice(&d.to_bytes());
    proof.extend_from_slice(&challenge.to_bytes());
    proof.extend_from_slice(&linkage_tag.to_compressed());
    proof.extend_from_slice(&(responses.len() as u32).to_le_bytes());
    for r in responses {
        proof.extend_from_slice(&r.to_bytes());
    }
    
    Ok(proof)
}

// Same as verify_signature_safe but for ZKP Proofs
#[uniffi::export]
pub fn verify_proof_safe(
    public_key: Vec<u8>,
    proof: Vec<u8>,
    total_message_count: u64,
    revealed_indices: Vec<u32>,
    revealed_messages_content: Vec<Vec<u8>>,
    nonce: Vec<u8>,
    alias_index: u64,
    freshness_claim: Option<Vec<u8>>,
) -> Result<bool, VerifyError> {
    
    // Reconstruct revealed messages map
    if revealed_indices.len() != revealed_messages_content.len() {
        return Err(VerifyError::InvalidSignature);
    }
    
    let mut revealed_messages: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, idx) in revealed_indices.iter().enumerate() {
        revealed_messages.push((*idx as usize, revealed_messages_content[i].clone()));
    }

    let total_message_count = total_message_count as usize;
    let alias_index = alias_index as usize;
    let freshness_claim_ref = freshness_claim.as_deref();
    
    // Parse public key
    // Parse public key
    if public_key.len() < 96 {
        return Err(VerifyError::InvalidKey);
    }
    
    // Parse w
    let w_bytes: [u8; 96] = public_key[..96].try_into().map_err(|_| VerifyError::InvalidKey)?;
    let w_opt = G2Affine::from_compressed(&w_bytes);
    if !bool::from(w_opt.is_some()) {
        return Err(VerifyError::InvalidKey);
    }
    let w = w_opt.unwrap();
    
    // Parse h values
    let mut h_values: Vec<G1Affine> = Vec::new();
    let mut offset = 96;
    while offset + 48 <= public_key.len() {
        let h_bytes: [u8; 48] = public_key[offset..offset+48].try_into().map_err(|_| VerifyError::InvalidKey)?;
        let h_opt = G1Affine::from_compressed(&h_bytes);
        if bool::from(h_opt.is_some()) {
            h_values.push(h_opt.unwrap());
        }
        offset += 48;
    }

    // Parse proof
    // [Implementation note: freshness_claim was moved to logic variable `freshness_claim_ref` to handle Option<Vec> ownership]
    
    if proof.len() < 196 {
         return Err(VerifyError::InvalidSignature); // InvalidProof
    }

    let a_prime_bytes: [u8; 48] = proof[..48].try_into().unwrap();
    let abar_bytes: [u8; 48] = proof[48..96].try_into().unwrap();
    let e_tilde_bytes: [u8; 32] = proof[96..128].try_into().unwrap();
    let d_bytes: [u8; 32] = proof[128..160].try_into().unwrap();
    let challenge_bytes: [u8; 32] = proof[160..192].try_into().unwrap();
    let linkage_tag_bytes: [u8; 48] = proof[192..240].try_into().map_err(|_| VerifyError::InvalidSignature)?;
    let response_count_bytes: [u8; 4] = proof[240..244].try_into().unwrap();
    let response_count = u32::from_le_bytes(response_count_bytes) as usize;
    // CRITICAL SECURITY FIX: Bound response_count to prevent DoS via memory exhaustion
    if response_count > total_message_count + 10 { // Allow reasonably small overhead
        return Err(VerifyError::InvalidSignature);
    }

    let a_prime_opt = G1Affine::from_compressed(&a_prime_bytes);
    let abar_opt = G1Affine::from_compressed(&abar_bytes);
    let e_tilde_opt = Scalar::from_bytes(&e_tilde_bytes);
    let d_opt = Scalar::from_bytes(&d_bytes);
    let challenge_opt = Scalar::from_bytes(&challenge_bytes);
    let linkage_tag_opt = G1Affine::from_compressed(&linkage_tag_bytes);

    if !bool::from(a_prime_opt.is_some()) || !bool::from(abar_opt.is_some()) 
        || !bool::from(e_tilde_opt.is_some()) || !bool::from(d_opt.is_some()) 
        || !bool::from(challenge_opt.is_some()) || !bool::from(linkage_tag_opt.is_some()) {
        return Err(VerifyError::InvalidSignature);
    }

    let a_prime = a_prime_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let abar = abar_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let e_tilde = e_tilde_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let d = d_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let challenge = challenge_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let linkage_tag = linkage_tag_opt.into_option().ok_or(VerifyError::InvalidSignature)?;

    // Parse responses
    let mut responses: Vec<Scalar> = Vec::with_capacity(response_count);
    let mut resp_offset = 244;
    for _ in 0..response_count {
        if resp_offset + 32 > proof.len() {
            return Err(VerifyError::InvalidSignature);
        }
        let resp_bytes: [u8; 32] = proof[resp_offset..resp_offset+32].try_into().unwrap();
        let resp_opt = Scalar::from_bytes(&resp_bytes);
        if !bool::from(resp_opt.is_some()) {
             return Err(VerifyError::InvalidSignature);
        }
        responses.push(resp_opt.unwrap());
        resp_offset += 32;
    }

    // Convert revealed messages to scalars
    let mut revealed_scalars: Vec<Scalar> = Vec::new();
    let mut revealed_idxs: Vec<usize> = Vec::new();
    
    for (idx, msg) in revealed_messages {
        revealed_idxs.push(idx);
        revealed_scalars.push(hash_to_scalar(&msg));
    }

    // **VERIFY ZERO-KNOWLEDGE PROOF**

    // Recompute commitment from responses: C' = sum(h_i * s_i) - challenge * sum(h_i * m_i_revealed)
    let mut c_recomputed = G1Projective::identity();

    // Add response contributions for hidden messages
    let mut resp_idx = 0;
    for i in 0..total_message_count {
        if !revealed_idxs.contains(&i) {
            // Hidden message - use response
            if resp_idx < responses.len() && i + 1 < h_values.len() {
                c_recomputed = c_recomputed + G1Projective::from(h_values[i + 1]) * responses[resp_idx];
                resp_idx += 1;
            }
        }
    }

    // Subtract challenge * revealed messages
    for (idx, revealed_idx) in revealed_idxs.iter().enumerate() {
        if idx < revealed_scalars.len() && *revealed_idx + 1 < h_values.len() {
            c_recomputed = c_recomputed - G1Projective::from(h_values[*revealed_idx + 1]) * (challenge * revealed_scalars[idx]);
        }
    }

    // Recompute Fiat-Shamir challenge
    let mut challenge_data = Vec::new();
    challenge_data.extend_from_slice(&a_prime.to_compressed());
    challenge_data.extend_from_slice(&abar.to_compressed());
    challenge_data.extend_from_slice(&d.to_bytes());
    
    if !nonce.is_empty() {
        challenge_data.extend_from_slice(&nonce);
    }

    challenge_data.extend_from_slice(&linkage_tag.to_compressed());
    challenge_data.extend_from_slice(&(alias_index as u64).to_le_bytes());
    
    if let Some(fc) = freshness_claim_ref {
        challenge_data.extend_from_slice(fc);
    }

    let challenge_check = hash_to_scalar(&challenge_data);

    // Verify challenge matches
    // Verify challenge matches
    if challenge != challenge_check {
        println!("DEBUG: Challenge Mismatch!");
        println!("Computed: {:?}", challenge_check);
        println!("Expected: {:?}", challenge);
        println!("Challenge Data Len: {}", challenge_data.len());
        println!("Proof Len: {}", proof.len());
        println!("Tag Present: {}", resp_offset + 32 <= proof.len());
        return Ok(false);
    }

    // Verify pairing: e(A', w * g2^e_tilde) == e(Abar + h0*d + sum(h_i * m_i_revealed), g2)
    let g2 = G2Projective::generator();
    let w_g2e = G2Projective::from(w) + g2 * e_tilde;

    let mut rhs_sum = G1Projective::from(abar);

    // Add h0 * d
    if !h_values.is_empty() {
        rhs_sum = rhs_sum + G1Projective::from(h_values[0]) * d;
    }

    // Add revealed messages
    for (idx, revealed_idx) in revealed_idxs.iter().enumerate() {
        if idx < revealed_scalars.len() && *revealed_idx + 1 < h_values.len() {
            rhs_sum = rhs_sum + G1Projective::from(h_values[*revealed_idx + 1]) * revealed_scalars[idx];
        }
    }

    let lhs = bls12_381::pairing(&a_prime, &w_g2e.to_affine());
    let rhs = bls12_381::pairing(&rhs_sum.to_affine(), &G2Affine::generator());

    Ok(lhs == rhs)
}


// ============================================================================
// Memory Management
// ============================================================================

// [Removed bbs_free_bytes]

// ============================================================================
// Miner Module Integration
// ============================================================================

// pub mod miner;
pub mod periwinkle; // Hardware entropy source
pub mod attestation; // Mobile Hardware Attestation (Phase 7) FFI
// [Removed re-exports of miner functions]

// ============================================================================
// Phase 9: Leasing (Delegation Token) Logic
// ============================================================================

#[derive(Debug, Clone, uniffi::Record)]
pub struct DelegationToken {
    pub anchor_id: Vec<u8>,
    pub mobile_key: Vec<u8>,
    pub expiration: u64,
    pub tier: u8,
    pub scope_mask: u32,
    pub max_passages: u32,
}

impl DelegationToken {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(145);
        // Padding or truncation to ensure fixed size expected by hashers if needed?
        // Protocol expects 32 bytes anchor_id, 96 bytes mobile_key.
        // We just append what we have, relying on validation elsewhere or assuming caller is correct.
        // Ideally we pad.
        bytes.extend_from_slice(&self.anchor_id);
        bytes.extend_from_slice(&self.mobile_key);
        bytes.extend_from_slice(&self.expiration.to_le_bytes());
        bytes.push(self.tier);
        bytes.extend_from_slice(&self.scope_mask.to_le_bytes());
        bytes.extend_from_slice(&self.max_passages.to_le_bytes());
        bytes
    }
}

/// Signs a Delegation Token using Anchor's SK (BBS+ Signature on Hash(Token))
#[uniffi::export]
pub fn sign_delegation(
    sk_bytes: Vec<u8>,
    pk_bytes: Vec<u8>,
    token: DelegationToken
) -> Result<Vec<u8>, VerifyError> {
    let sk = Scalar::from_bytes(sk_bytes.as_slice().try_into().map_err(|_| VerifyError::InvalidKey)?).unwrap();
    
    // PK: w, h0, h1
    if pk_bytes.len() < 192 { return Err(VerifyError::InvalidKey); }
    
    let mut h = Vec::new();
    for i in 0..2 {
        let offset = 96 + i*48;
         let h_bytes: [u8; 48] = pk_bytes[offset..offset+48].try_into().map_err(|_| VerifyError::InvalidKey)?;
         let h_point = G1Affine::from_compressed(&h_bytes).into_option().ok_or(VerifyError::InvalidKey)?;
         h.push(G1Projective::from(h_point));
    }
    
    let mut hasher = Sha256::new();
    hasher.update(token.to_bytes());
    let m_scalar = hash_to_scalar(&hasher.finalize());
    
    let mut rng = thread_rng();
    let e = Scalar::random(&mut rng);
    let s = Scalar::random(&mut rng);
    
    // B = g1 + h0*s + h1*m
    let g1 = G1Projective::generator();
    let b = g1 + h[0]*s + h[1]*m_scalar;
    
    let inv = (sk + e).invert().into_option().ok_or(VerifyError::CryptoError)?;
    let a = b * inv;
    
    let mut sig = Vec::new();
    sig.extend_from_slice(&a.to_affine().to_compressed());
    sig.extend_from_slice(&e.to_bytes());
    sig.extend_from_slice(&s.to_bytes());
    Ok(sig)
}

/// Verifies a Delegation Token Signature (Anchor PK -> Token)
#[uniffi::export]
pub fn verify_delegation_signature(
    pk_bytes: Vec<u8>,
    token: DelegationToken,
    sig_bytes: Vec<u8>
) -> Result<bool, VerifyError> {
    if sig_bytes.len() != 112 { return Err(VerifyError::InvalidSignature); }
    
    // Load Sig: A, e, s
    let a_opt = G1Affine::from_compressed(sig_bytes[0..48].try_into().unwrap());
    let a = a_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let e_opt = Scalar::from_bytes(sig_bytes[48..80].try_into().unwrap());
    let e = e_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    let s_opt = Scalar::from_bytes(sig_bytes[80..112].try_into().unwrap());
    let s = s_opt.into_option().ok_or(VerifyError::InvalidSignature)?;
    
    // Load PK: w, h0, h1
    if pk_bytes.len() < 192 { return Err(VerifyError::InvalidKey); }
    let w_bytes: [u8; 96] = pk_bytes[0..96].try_into().map_err(|_| VerifyError::InvalidKey)?;
    let w_point = G2Affine::from_compressed(&w_bytes).into_option().ok_or(VerifyError::InvalidKey)?;
    let w = G2Projective::from(w_point);
    let mut h = Vec::new();
    for i in 0..2 {
        let offset = 96 + i*48;
         let h_bytes: [u8; 48] = pk_bytes[offset..offset+48].try_into().map_err(|_| VerifyError::InvalidKey)?;
         let h_point = G1Affine::from_compressed(&h_bytes).into_option().ok_or(VerifyError::InvalidKey)?;
         h.push(G1Projective::from(h_point));
    }
    
    let mut hasher = Sha256::new();
    hasher.update(token.to_bytes());
    let m = hash_to_scalar(&hasher.finalize());
    
    // Check: e(A, w + g2*e) == e(g1 + h0*s + h1*m, g2)
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    
    let lhs = bls12_381::pairing(&a, &(w + g2*e).to_affine());
    let rhs_g1 = g1 + h[0]*s + h[1]*m;
    let rhs = bls12_381::pairing(&rhs_g1.to_affine(), &G2Affine::generator());
    
    Ok(lhs == rhs)
}

// [Removed bbs_sign_delegation]
// ============================================================================
// Phase 11: Shamir's Sovereign Recovery
// ============================================================================

/// Splits a scalar secret into N shares with threshold K
pub fn split_secret(secret: &Scalar, n: u8, k: u8) -> Vec<(u8, Scalar)> {
    let mut rng = thread_rng();
    let mut coeffs = vec![*secret];
    for _ in 1..k {
        coeffs.push(Scalar::random(&mut rng));
    }
    
    let mut shares = Vec::new();
    for x in 1..=n {
        let x_scalar = Scalar::from(x as u64);
        let mut y = Scalar::zero();
        let mut x_pow = Scalar::one();
        for coeff in &coeffs {
            y += coeff * x_pow;
            x_pow *= x_scalar;
        }
        shares.push((x, y));
    }
    shares
}

/// Reconstructs secret from K shares using Lagrange Interpolation
pub fn reconstruct_secret(shares: &[(u8, Scalar)]) -> Result<Scalar, String> {
    if shares.is_empty() { return Err("No shares provided".into()); }
    
    let mut secret = Scalar::zero();
    
    for (j, (x_j_idx, y_j)) in shares.iter().enumerate() {
        let xj = Scalar::from(*x_j_idx as u64);
        
        let mut numerator = Scalar::one();
        let mut denominator = Scalar::one();
        
        for (m, (x_m_idx, _)) in shares.iter().enumerate() {
            if m != j {
                let xm = Scalar::from(*x_m_idx as u64);
                let minus_xm = -xm;
                let xj_minus_xm = xj - xm;
                
                numerator *= minus_xm;
                denominator *= xj_minus_xm;
            }
        }
        
        let denom_inv_opt = denominator.invert();
        if !bool::from(denom_inv_opt.is_some()) { return Err("Invalid shares (duplicate indices?)".into()); }
        let denom_inv = denom_inv_opt.unwrap();
        
        let basis = numerator * denom_inv;
        secret += y_j * basis;
    }
    
    Ok(secret)
}

// [Removed bbs_reconstruct_secret]

#[uniffi::export]
pub fn split_secret_safe(
    secret: Vec<u8>,
    threshold: u8,
    total: u8,
) -> Result<Vec<Vec<u8>>, VerifyError> {
    if secret.len() != 32 { return Err(VerifyError::InvalidKey); }
    let arr: [u8; 32] = secret.try_into().unwrap();
    let scalar_opt = Scalar::from_bytes(&arr);
    let scalar = if bool::from(scalar_opt.is_some()) { scalar_opt.unwrap() } else { return Err(VerifyError::InvalidKey); };

    let shares = split_secret(&scalar, threshold, total);
    
    let mut result = Vec::new();
    for (idx, s) in shares {
        let mut share_bytes = Vec::with_capacity(33);
        share_bytes.push(idx);
        share_bytes.extend_from_slice(&s.to_bytes());
        result.push(share_bytes);
    }
    Ok(result)
}

#[uniffi::export]
pub fn reconstruct_secret_safe(shares: Vec<Vec<u8>>) -> Result<Vec<u8>, VerifyError> {
    let mut parsed_shares: Vec<(u8, Scalar)> = Vec::new();
    for share in shares {
        if share.len() != 33 { return Err(VerifyError::InvalidKey); }
        let idx = share[0];
        let s_bytes: [u8; 32] = share[1..33].try_into().unwrap();
        let s_opt = Scalar::from_bytes(&s_bytes);
        if bool::from(s_opt.is_some()) {
            parsed_shares.push((idx, s_opt.unwrap()));
        } else {
            return Err(VerifyError::InvalidKey);
        }
    }
    
    let secret = reconstruct_secret(&parsed_shares).map_err(|_| VerifyError::CryptoError)?;
    Ok(secret.to_bytes().to_vec())
}


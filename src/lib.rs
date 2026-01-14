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

// pub mod anchor; // Scripts are in separate repo
// pub mod oidc; // Server only
pub mod multipass;
// pub mod db; // Server only

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
// Safe Rust Verification API
// ============================================================================

#[derive(Debug)]
pub enum VerifyError {
    InvalidKey,
    InvalidSignature,
    CryptoError,
}

pub fn verify_signature_safe(
    public_key: &[u8],
    signature: &[u8],
    messages: &[Vec<u8>],
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

// [Removed bbs_create_proof]

// [Removed bbs_verify_proof]

// Same as verify_signature_safe but for ZKP Proofs
pub fn verify_proof_safe(
    public_key: &[u8],
    proof: &[u8],
    total_message_count: usize,
    revealed_messages: &[(usize, Vec<u8>)], // Index + Content
    nonce: &[u8],
    alias_index: usize,
    freshness_claim: Option<&[u8]>,
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

    // Parse proof
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
        revealed_idxs.push(*idx);
        revealed_scalars.push(hash_to_scalar(msg));
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
        challenge_data.extend_from_slice(nonce);
    }

    challenge_data.extend_from_slice(&linkage_tag.to_compressed());
    challenge_data.extend_from_slice(&(alias_index as u64).to_le_bytes());
    
    if let Some(fc) = freshness_claim {
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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DelegationToken {
    pub anchor_id: [u8; 32],
    pub mobile_key: [u8; 96], // G2 Public Key
    pub expiration: u64,
    pub tier: u8,
    pub scope_mask: u32,
    pub max_passages: u32,
}

impl DelegationToken {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(145);
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
pub fn sign_delegation(
    sk_bytes: &[u8],
    pk_bytes: &[u8],
    token: &DelegationToken
) -> Result<Vec<u8>, String> {
    let sk = Scalar::from_bytes(sk_bytes.try_into().map_err(|_| "Invalid SK")?).unwrap();
    
    // PK: w, h0, h1
    // We sign 1 message: m1 = Hash(Token)
    // Need w(48) + h0(48) + h1(48) = 144 bytes min
    if pk_bytes.len() < 192 { return Err("PK too short".into()); }
    
    let mut h = Vec::new();
    for i in 0..2 {
        let offset = 96 + i*48;
         let h_bytes: [u8; 48] = pk_bytes[offset..offset+48].try_into().map_err(|_| "PK Offset Error")?;
         let h_point = G1Affine::from_compressed(&h_bytes).into_option().ok_or("Invalid PK generator")?;
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
    
    let inv = (sk + e).invert().into_option().ok_or("SK+e Inversion Failed")?;
    let a = b * inv;
    
    let mut sig = Vec::new();
    sig.extend_from_slice(&a.to_affine().to_compressed());
    sig.extend_from_slice(&e.to_bytes());
    sig.extend_from_slice(&s.to_bytes());
    Ok(sig)
}

/// Verifies a Delegation Token Signature (Anchor PK -> Token)
pub fn verify_delegation_signature(
    pk_bytes: &[u8],
    token: &DelegationToken,
    sig_bytes: &[u8]
) -> Result<bool, String> {
    if sig_bytes.len() != 112 { return Err("Invalid sig len".into()); }
    
    // Load Sig: A, e, s
    let a_opt = G1Affine::from_compressed(sig_bytes[0..48].try_into().unwrap());
    let a = a_opt.into_option().ok_or("Invalid A in sig")?;
    let e_opt = Scalar::from_bytes(sig_bytes[48..80].try_into().unwrap());
    let e = e_opt.into_option().ok_or("Invalid e in sig")?;
    let s_opt = Scalar::from_bytes(sig_bytes[80..112].try_into().unwrap());
    let s = s_opt.into_option().ok_or("Invalid s in sig")?;
    
    // Load PK: w, h0, h1
    if pk_bytes.len() < 192 { return Err("PK too short".into()); }
    let w_bytes: [u8; 96] = pk_bytes[0..96].try_into().map_err(|_| "PK Read Error")?;
    let w_point = G2Affine::from_compressed(&w_bytes).into_option().ok_or("Invalid w in PK")?;
    let w = G2Projective::from(w_point);
    let mut h = Vec::new();
    for i in 0..2 {
        let offset = 96 + i*48;
         let h_bytes: [u8; 48] = pk_bytes[offset..offset+48].try_into().map_err(|_| "PK Offset Error")?;
         let h_point = G1Affine::from_compressed(&h_bytes).into_option().ok_or("Invalid h in PK")?;
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

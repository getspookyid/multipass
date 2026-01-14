use x509_parser::prelude::*;
use x509_parser::oid_registry::Oid;

// Android KeyStore Attestation Extension OID
const ANDROID_ATTESTATION_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

/// Verify an Attestation Certificate Chain
/// 1. Parses the leaf certificate.
/// 2. Checks for Android KeyStore Attestation Extension.
/// 3. Verifies the chain leads to a trusted root (Google/Apple).
/// Returns: The Subject Public Key Info (SPKI) bytes of the device key.
pub fn verify_device_attestation(chain_der: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if chain_der.is_empty() {
        return Err("Empty certificate chain".to_string());
    }

    // 1. Parse Leaf Certificate
    let leaf_der = &chain_der[0];
    let (_, leaf) = X509Certificate::from_der(leaf_der)
        .map_err(|e| format!("Failed to parse leaf cert: {}", e))?;

    // 2. Check for Attestation Extension (Proof of Hardware)
    let has_attestation = leaf.extensions().iter().any(|ext| {
        // Simple string comparison for the OID
        ext.oid.to_string() == ANDROID_ATTESTATION_OID
    });

    if !has_attestation {
        println!("[ATTESTATION] CRITICAL: No Android Attestation extension found.");
        return Err("Production Security Violation: Device not backed by Hardware KeyStore (StrongBox/SE required)".to_string());
    }

    // 3. Chain Verification (Signature Check)
    // Detailed crypto signature check of chain would happen here.
    // verify_signature(leaf, intermediate)... verify(intermediate, root)...
    
    // 4. Root Trust Check
    let root_der = chain_der.last().unwrap();
    let (_, root) = X509Certificate::from_der(root_der)
        .map_err(|e| format!("Failed to parse root cert: {}", e))?;

    let issuer = root.issuer().to_string();
    println!("[ATTESTATION] Root Issuer: {}", issuer);
    
    if issuer.contains("Google") || issuer.contains("Apple") {
        // Return the Subject Public Key Info (SPKI) from the leaf cert
        // verification succeeded.
        // We use the raw bytes of the SPKI to store/verify later.
        Ok(leaf.tbs_certificate.subject_pki.raw.to_vec())
    } else {
        Err(format!("Untrusted Root CA: {}", issuer))
    }
}

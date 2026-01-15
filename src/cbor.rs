use ciborium::{cbor, ser};
use coset::{CoseSign1Builder, HeaderBuilder, iana, CborSerializable};
use p256::ecdsa::{SigningKey, Signature, signature::Signer};
use serde::Serialize;
use std::error::Error;

/// CBOR encoding with SpookyID domain separation
pub struct SpookyCBOR;

impl SpookyCBOR {
    /// Encode mdoc-compatible CBOR with domain tag
    pub fn encode_mdoc_element<T: Serialize>(
        value: &T,
        doc_type: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut buffer = Vec::new();
        
        // Domain separation per SpookyID Master Directive v4.0
        // ISO 18013-5 requires tagged CBOR (Section 7.2.1)
        ser::into_writer(&cbor!({
            "docType" => doc_type,
            "domainTag" => format!("SpookyID.mdoc.{}.v1", doc_type),
            "data" => value,
        })?, &mut buffer)?;
        
        Ok(buffer)
    }
    
    /// Create COSE_Sign1 structure for Mobile Security Object (MSO)
    pub fn create_mso_signature(
        mso_bytes: &[u8],
        issuer_key: &SigningKey,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        
        // COSE_Sign1 with ES256
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES256)
            .build();
        
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(mso_bytes.to_vec())
            .create_signature(b"", |data| {
                let sig: Signature = issuer_key.sign(data);
                sig.to_bytes().to_vec()
            })
            .build();
        
        Ok(sign1.to_vec().map_err(|e| format!("Cose error: {:?}", e))?)
    }
}

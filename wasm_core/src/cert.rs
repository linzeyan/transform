//! TLS/SSL certificate inspection helpers. Accepts PEM-encoded certificates or
//! DER blobs and returns structured metadata suitable for the Wasm bindings.
use std::collections::HashMap;

#[cfg(target_arch = "wasm32")]
use ::time::Duration;
use ::time::{OffsetDateTime, format_description::well_known::Rfc3339};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_parser::certificate::Validity;
use x509_parser::extensions::{
    ExtendedKeyUsage, GeneralName, KeyUsage, ParsedExtension, SubjectAlternativeName,
};
use x509_parser::objects::{oid_registry, oid2sn};
use x509_parser::oid_registry::Oid;
use x509_parser::pem::Pem;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;
use x509_parser::time::ASN1Time;

/// Summary of a single X.509 certificate with common fields surfaced for UI use.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CertificateSummary {
    /// 1-based position in the provided chain so the UI can preserve user order.
    pub position: usize,
    pub subject: String,
    pub subject_common_name: Option<String>,
    pub issuer: String,
    pub issuer_common_name: Option<String>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub days_valid_from_now: Option<i64>,
    pub is_expired: bool,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: u32,
    pub subject_alt_names: Vec<String>,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    pub basic_constraints: Option<BasicConstraintsSummary>,
    pub fingerprints: Fingerprints,
    pub authority_key_id: Option<String>,
    pub subject_key_id: Option<String>,
    pub issuer_position: Option<usize>,
    pub is_self_signed: bool,
}

/// Extracted BasicConstraints extension data.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BasicConstraintsSummary {
    pub ca: bool,
    pub path_len: Option<u32>,
}

/// SHA fingerprints for quick comparison in the UI.
#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprints {
    pub sha1: String,
    pub sha256: String,
    pub spki_sha256: String,
}

/// Parses one or more PEM/DER certificates and returns structured metadata.
pub fn inspect_certificates_internal(input: &str) -> Result<Vec<CertificateSummary>, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("certificate input cannot be empty".into());
    }
    let mut der_blobs = collect_der_blobs(trimmed)?;
    if der_blobs.is_empty() {
        return Err("no certificates found in input".into());
    }

    let mut summaries = Vec::with_capacity(der_blobs.len());
    for (idx, der) in der_blobs.iter_mut().enumerate() {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|err| format!("failed to parse certificate #{idx}: {err}"))?;
        let subject = cert.subject().to_string();
        let issuer = cert.issuer().to_string();

        let subject_common_name = first_common_name(cert.subject());
        let issuer_common_name = first_common_name(cert.issuer());

        let serial_hex = hex::encode_upper(cert.raw_serial());
        let not_before = format_time(cert.validity().not_before);
        let not_after = format_time(cert.validity().not_after);
        let (is_expired, days_valid_from_now) = expiry_status(cert.validity());

        let signature_algorithm = describe_oid(&cert.signature_algorithm.algorithm);
        let (public_key_algorithm, public_key_bits) = describe_public_key(cert.public_key());

        let mut subject_alt_names = Vec::new();
        let mut key_usage = Vec::new();
        let mut extended_key_usage = Vec::new();
        let mut basic_constraints = None;
        let mut authority_key_id = None;
        let mut subject_key_id = None;

        for ext in cert.extensions() {
            match &ext.parsed_extension() {
                ParsedExtension::SubjectAlternativeName(san) => {
                    subject_alt_names = render_subject_alt_names(san);
                }
                ParsedExtension::KeyUsage(usage) => {
                    key_usage = render_key_usage(usage);
                }
                ParsedExtension::ExtendedKeyUsage(eku) => {
                    extended_key_usage = render_extended_key_usage(eku);
                }
                ParsedExtension::BasicConstraints(bc) => {
                    basic_constraints = Some(BasicConstraintsSummary {
                        ca: bc.ca,
                        path_len: bc.path_len_constraint,
                    });
                }
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    authority_key_id = aki
                        .key_identifier
                        .as_ref()
                        .map(|id| hex::encode_upper(id.0));
                }
                ParsedExtension::SubjectKeyIdentifier(ski) => {
                    subject_key_id = Some(hex::encode_upper(ski.0));
                }
                _ => {}
            }
        }

        let fingerprints = Fingerprints {
            sha1: hex::encode_upper(Sha1::digest(der.as_slice())),
            sha256: hex::encode_upper(Sha256::digest(der.as_slice())),
            spki_sha256: hex::encode_upper(spki_fingerprint(cert.public_key())),
        };

        let summary = CertificateSummary {
            position: idx + 1,
            subject,
            subject_common_name,
            issuer,
            issuer_common_name,
            serial_hex,
            not_before,
            not_after,
            days_valid_from_now,
            is_expired,
            signature_algorithm,
            public_key_algorithm,
            public_key_bits,
            subject_alt_names,
            key_usage,
            extended_key_usage,
            basic_constraints,
            fingerprints,
            authority_key_id,
            subject_key_id,
            issuer_position: None,
            is_self_signed: false,
        };
        summaries.push(summary);
    }

    link_issuers(&mut summaries);
    Ok(summaries)
}

fn collect_der_blobs(input: &str) -> Result<Vec<Vec<u8>>, String> {
    let mut blobs = Vec::new();
    let mut pem_found = false;
    for pem_res in Pem::iter_from_buffer(input.as_bytes()) {
        match pem_res {
            Ok(pem) => {
                pem_found = true;
                if pem.label.ends_with("CERTIFICATE") {
                    blobs.push(pem.contents);
                }
            }
            Err(_) => continue,
        }
    }
    if pem_found {
        return Ok(blobs);
    }
    if let Ok(decoded) = STANDARD.decode(input) {
        blobs.push(decoded);
        return Ok(blobs);
    }
    // Fallback: treat as raw DER if parse succeeds; otherwise propagate an error.
    if X509Certificate::from_der(input.as_bytes()).is_ok() {
        blobs.push(input.as_bytes().to_vec());
        Ok(blobs)
    } else {
        Err("input was neither PEM nor base64/DER".into())
    }
}

fn format_time(time: ASN1Time) -> String {
    time.to_datetime()
        .format(&Rfc3339)
        .unwrap_or_else(|_| time.to_string())
}

fn expiry_status(validity: &Validity) -> (bool, Option<i64>) {
    let now = current_utc();
    let end = validity.not_after.to_datetime();
    let expired = now > end;
    let days = Some((end - now).whole_days());
    (expired, days)
}

fn current_utc() -> OffsetDateTime {
    #[cfg(target_arch = "wasm32")]
    {
        let millis = js_sys::Date::now() as i64;
        return OffsetDateTime::UNIX_EPOCH + Duration::milliseconds(millis);
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        OffsetDateTime::now_utc()
    }
}

fn describe_oid(oid: &Oid) -> String {
    oid2sn(oid, oid_registry())
        .map(str::to_string)
        .unwrap_or_else(|_| oid.to_id_string())
}

fn describe_public_key(spki: &SubjectPublicKeyInfo<'_>) -> (String, u32) {
    let algo = describe_oid(&spki.algorithm.algorithm);
    let mut bit_len = spki.subject_public_key.data.len() as u32 * 8;
    if let Ok(parsed) = spki.parsed() {
        let parsed_bits = match parsed {
            PublicKey::RSA(rsa) => rsa.key_size() as u32,
            PublicKey::EC(ec) => ec.key_size() as u32,
            PublicKey::DSA(bytes)
            | PublicKey::GostR3410(bytes)
            | PublicKey::GostR3410_2012(bytes) => (bytes.len() as u32) * 8,
            _ => 0,
        };
        if parsed_bits > 0 {
            bit_len = parsed_bits;
        }
    }
    (algo, bit_len)
}

fn render_subject_alt_names(san: &SubjectAlternativeName<'_>) -> Vec<String> {
    san.general_names
        .iter()
        .map(describe_general_name)
        .filter(|val| !val.is_empty())
        .collect()
}

fn describe_general_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::DNSName(val) => format!("DNS:{val}"),
        GeneralName::URI(val) => format!("URI:{val}"),
        GeneralName::RFC822Name(val) => format!("Email:{val}"),
        GeneralName::IPAddress(bytes) => format!("IP:{}", format_ip(bytes)),
        GeneralName::DirectoryName(dir) => format!("DirName:{dir}"),
        _ => String::new(),
    }
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join("."),
        16 => bytes
            .chunks(2)
            .map(|pair| {
                let high = pair[0] as u16;
                let low = pair[1] as u16;
                format!("{:x}", (high << 8) | low)
            })
            .collect::<Vec<_>>()
            .join(":"),
        _ => hex::encode_upper(bytes),
    }
}

fn render_key_usage(usage: &KeyUsage) -> Vec<String> {
    let mut out = Vec::new();
    if usage.digital_signature() {
        out.push("digitalSignature".into());
    }
    if usage.non_repudiation() {
        out.push("contentCommitment".into());
    }
    if usage.key_encipherment() {
        out.push("keyEncipherment".into());
    }
    if usage.data_encipherment() {
        out.push("dataEncipherment".into());
    }
    if usage.key_agreement() {
        out.push("keyAgreement".into());
    }
    if usage.key_cert_sign() {
        out.push("keyCertSign".into());
    }
    if usage.crl_sign() {
        out.push("crlSign".into());
    }
    if usage.encipher_only() {
        out.push("encipherOnly".into());
    }
    if usage.decipher_only() {
        out.push("decipherOnly".into());
    }
    out
}

fn render_extended_key_usage(eku: &ExtendedKeyUsage<'_>) -> Vec<String> {
    let mut values = Vec::new();
    if eku.any {
        values.push("anyExtendedKeyUsage".into());
    }
    if eku.server_auth {
        values.push("serverAuth".into());
    }
    if eku.client_auth {
        values.push("clientAuth".into());
    }
    if eku.code_signing {
        values.push("codeSigning".into());
    }
    if eku.email_protection {
        values.push("emailProtection".into());
    }
    if eku.time_stamping {
        values.push("timeStamping".into());
    }
    if eku.ocsp_signing {
        values.push("ocspSigning".into());
    }
    for oid in &eku.other {
        values.push(describe_oid(oid));
    }
    values
}

fn spki_fingerprint(spki: &SubjectPublicKeyInfo<'_>) -> Vec<u8> {
    Sha256::digest(spki.subject_public_key.data.as_ref()).to_vec()
}

fn first_common_name(rdn: &X509Name<'_>) -> Option<String> {
    rdn.iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().map(|s| s.to_string()).ok())
}

fn link_issuers(summaries: &mut [CertificateSummary]) {
    let mut ski_to_pos: HashMap<String, usize> = HashMap::new();
    for summary in summaries.iter() {
        if let Some(ref ski) = summary.subject_key_id {
            ski_to_pos.insert(ski.clone(), summary.position);
        }
    }
    for summary in summaries.iter_mut() {
        summary.is_self_signed = summary.subject == summary.issuer;
        if let Some(ref aki) = summary.authority_key_id {
            if let Some(pos) = ski_to_pos.get(aki) {
                summary.issuer_position = Some(*pos);
            }
        }
    }
}

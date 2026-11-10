//! Writes `cawg.identity` assertions (CAWG Identity Assertion 1.3).
//!
//! c2pa-rs's `IdentityAssertionBuilder` only writes valid assertions, so this module builds the
//! assertion itself as a C2PA dynamic assertion: it chooses the referenced assertions, gets the
//! signature from an X.509 credential holder or a local identity claims aggregation issuer, and
//! pads the CBOR to the reserved size. Each [`Defect`] breaks exactly one rule so that the
//! invalid fixtures each exercise one status code.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use c2pa::{
    dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim},
    identity::{builder::CredentialHolder, x509::X509CredentialHolder, SignerPayload},
    BoxedSigner, HashedUri, Signer, SigningAlg,
};
use coset::{iana, CoseSign1, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable};
use serde::Serialize;
use serde_json::{json, Value};

use crate::pki::{IcaIssuer, Leaf};

pub const X509_SIG_TYPE: &str = "cawg.x509.cose";
pub const ICA_SIG_TYPE: &str = "cawg.identity_claims_aggregation";

/// How the named actor's credential signs the signer payload.
pub enum Credential {
    /// `cawg.x509.cose`: a COSE_Sign1 by the actor's own X.509 certificate.
    X509(Leaf),
    /// `cawg.identity_claims_aggregation`: a W3C verifiable credential from an identity
    /// aggregator, as a COSE_Sign1 with an embedded payload.
    Ica(Ica),
    /// An unrecognised `sig_type` with an arbitrary signature.
    Unknown(&'static str),
}

pub struct Ica {
    pub issuer: Arc<IcaIssuer>,
    /// `credentialSubject.verifiedIdentities`.
    pub identities: Value,
    /// Overrides the issuer's `did:jwk` as the VC `issuer`.
    pub issuer_did: Option<String>,
    /// `validFrom`; `None` omits it.
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    /// Extra top-level VC properties, such as `credentialStatus`.
    pub extra: Value,
    /// The COSE `content type` header; `None` omits it.
    pub content_type: Option<&'static str>,
    pub alg: iana::Algorithm,
}

impl Ica {
    pub fn new(issuer: &Arc<IcaIssuer>, identities: Value) -> Self {
        Self {
            issuer: issuer.clone(),
            identities,
            issuer_did: None,
            valid_from: Some("2026-01-01T00:00:00Z".to_owned()),
            valid_until: None,
            extra: json!({}),
            content_type: Some("application/vc"),
            alg: iana::Algorithm::EdDSA,
        }
    }
}

/// One deliberate violation of the identity assertion rules.
#[derive(Clone, Copy, PartialEq)]
pub enum Defect {
    /// A bit of the COSE signature flipped after signing.
    CorruptSignature,
    /// The X.509 COSE `alg` header changed to RS256, which C2PA doesn't allow.
    UnsupportedAlgorithm,
    /// `pad1` filled with 0x01 instead of zeros.
    NonZeroPad,
    /// `signer_payload` omitted.
    MissingSignerPayload,
    /// `role` present as an empty array; the CDDL requires at least one entry.
    EmptyRole,
    /// The claim's hard binding left out of `referenced_assertions`.
    NoHardBinding,
    /// One referenced assertion listed twice.
    DuplicateReference,
    /// The hash of a referenced assertion changed, so it doesn't match the claim.
    StaleReference,
    /// The signature covers a different `referenced_assertions` than the one in the
    /// assertion (ICA: `c2paAsset` doesn't match `signer_payload`).
    SignedDifferentPayload,
}

/// A `cawg.identity` assertion to add when the claim is signed.
pub struct Identity {
    pub credential: Credential,
    pub roles: Vec<&'static str>,
    /// Labels of assertions in this claim to reference, besides the hard binding.
    pub references: Vec<&'static str>,
    /// Assertions in an ingredient's claim to reference (absolute JUMBF URIs).
    pub ingredient_references: Vec<HashedUri>,
    /// Referenced instead of this claim's own hard binding.
    pub foreign_hard_binding: Option<HashedUri>,
    pub defects: Vec<Defect>,
}

impl Identity {
    pub fn new(credential: Credential, roles: &[&'static str], references: &[&'static str]) -> Self {
        Self {
            credential,
            roles: roles.to_vec(),
            references: references.to_vec(),
            ingredient_references: vec![],
            foreign_hard_binding: None,
            defects: vec![],
        }
    }

    pub fn with(mut self, defect: Defect) -> Self {
        self.defects.push(defect);
        self
    }

    fn has(&self, defect: Defect) -> bool {
        self.defects.contains(&defect)
    }

    fn sig_type(&self) -> &'static str {
        match &self.credential {
            Credential::X509(_) => X509_SIG_TYPE,
            Credential::Ica(_) => ICA_SIG_TYPE,
            Credential::Unknown(t) => t,
        }
    }

    fn reserve(&self) -> usize {
        match &self.credential {
            Credential::X509(leaf) => 4096 + leaf.chain.iter().map(Vec::len).sum::<usize>(),
            Credential::Ica(ica) => 8192 + ica.identities.to_string().len() + ica.extra.to_string().len(),
            Credential::Unknown(_) => 2048,
        }
    }

    fn signer_payload(&self, claim: &PartialClaim) -> SignerPayload {
        let label = |uri: &HashedUri| uri.url().rsplit_once('/').map(|(_, l)| l.to_owned()).unwrap_or_default();
        let mut referenced: Vec<HashedUri> = claim
            .assertions()
            .filter(|a| {
                let l = label(a);
                (l.starts_with("c2pa.hash.") && !self.has(Defect::NoHardBinding) && self.foreign_hard_binding.is_none())
                    || self.references.contains(&l.as_str())
            })
            .cloned()
            .collect();
        referenced.extend(self.foreign_hard_binding.iter().cloned());
        referenced.extend(self.ingredient_references.iter().cloned());
        if self.has(Defect::DuplicateReference) {
            let extra = referenced.iter().find(|a| !label(a).starts_with("c2pa.hash.")).cloned();
            referenced.extend(extra);
        }
        if self.has(Defect::StaleReference) {
            if let Some(a) = referenced.iter_mut().find(|a| !label(a).starts_with("c2pa.hash.")) {
                let mut hash = a.hash();
                hash[0] ^= 0xff;
                *a = HashedUri::new(a.url(), a.alg(), &hash);
            }
        }
        SignerPayload {
            referenced_assertions: referenced,
            sig_type: self.sig_type().to_owned(),
            roles: self.roles.iter().map(|r| r.to_string()).collect(),
        }
    }

    fn sign(&self, payload: &SignerPayload) -> Result<Vec<u8>> {
        // The payload the credential actually signs.
        let mut signed = payload.clone();
        if self.has(Defect::SignedDifferentPayload) {
            signed.referenced_assertions.truncate(1);
        }
        let mut signature = match &self.credential {
            Credential::X509(leaf) => {
                let raw = c2pa_raw_crypto::signer_from_private_key(&leaf.key_pem, leaf.alg)?;
                X509CredentialHolder::from_raw_signer(raw, leaf.chain.clone())
                    .sign(&signed)
                    .map_err(|e| anyhow!("X.509 identity signature: {e}"))?
            }
            Credential::Ica(ica) => sign_ica(ica, &signed)?,
            Credential::Unknown(_) => b"not a signature this validator understands".to_vec(),
        };
        if self.has(Defect::CorruptSignature) || self.has(Defect::UnsupportedAlgorithm) {
            let mut sign1 = CoseSign1::from_tagged_slice(&signature).map_err(|e| anyhow!("{e:?}"))?;
            if self.has(Defect::CorruptSignature) {
                *sign1.signature.last_mut().unwrap() ^= 0x01;
            }
            if self.has(Defect::UnsupportedAlgorithm) {
                sign1.protected.original_data = None;
                sign1.protected.header.alg = Some(coset::Algorithm::Assigned(iana::Algorithm::RS256));
            }
            signature = sign1.to_tagged_vec().map_err(|e| anyhow!("{e:?}"))?;
        }
        Ok(signature)
    }

    fn content(&self, size: Option<usize>, claim: &PartialClaim) -> Result<Vec<u8>> {
        let payload = self.signer_payload(claim);
        let signature = self.sign(&payload)?;
        let mut payload = c2pa_cbor::to_value(&payload)?;
        if self.has(Defect::EmptyRole) {
            if let c2pa_cbor::Value::Map(m) = &mut payload {
                m.insert(c2pa_cbor::Value::Text("role".into()), c2pa_cbor::Value::Array(vec![]));
            }
        }
        let mut ia = Wire {
            signer_payload: (!self.has(Defect::MissingSignerPayload)).then_some(payload),
            signature,
            pad1: vec![],
            pad2: None,
        };
        let pad = if self.has(Defect::NonZeroPad) { 1 } else { 0 };
        let Some(size) = size else { return Ok(c2pa_cbor::to_vec(&ia)?) };
        // As c2pa-rs does: size pad1 first, then make up the remaining bytes with pad2.
        let len = c2pa_cbor::to_vec(&ia)?.len();
        anyhow::ensure!(size >= len + 15, "identity assertion is {len} bytes, more than the {size} reserved");
        ia.pad1 = vec![pad; size - len - 15];
        let len = c2pa_cbor::to_vec(&ia)?.len();
        ia.pad2 = Some(serde_bytes::ByteBuf::from(vec![0u8; size - len - 6]));
        let cbor = c2pa_cbor::to_vec(&ia)?;
        anyhow::ensure!(cbor.len() == size, "padded identity assertion is {} bytes, not {size}", cbor.len());
        Ok(cbor)
    }
}

#[derive(Serialize)]
struct Wire {
    #[serde(skip_serializing_if = "Option::is_none")]
    signer_payload: Option<c2pa_cbor::Value>,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pad1: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pad2: Option<serde_bytes::ByteBuf>,
}

/// The ICA verifiable credential for `payload` (Identity 1.3 §8.1.2), signed by its issuer.
fn sign_ica(ica: &Ica, payload: &SignerPayload) -> Result<Vec<u8>> {
    // §8.1.2.4: c2paAsset is signer_payload in JSON, with byte strings as base64 text.
    let refs: Vec<Value> = payload
        .referenced_assertions
        .iter()
        .map(|a| {
            let mut r = json!({ "url": a.url(), "hash": BASE64.encode(a.hash()) });
            if let Some(alg) = a.alg() {
                r["alg"] = json!(alg);
            }
            r
        })
        .collect();
    let mut asset = json!({ "referenced_assertions": refs, "sig_type": payload.sig_type });
    if !payload.roles.is_empty() {
        asset["role"] = json!(payload.roles);
    }
    let mut vc = json!({
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://cawg.io/identity/1.1/ica/context/"],
        "type": ["VerifiableCredential", "IdentityClaimsAggregationCredential"],
        "issuer": ica.issuer_did.as_deref().unwrap_or(&ica.issuer.did),
        "credentialSubject": { "verifiedIdentities": ica.identities, "c2paAsset": asset },
    });
    if let Some(from) = &ica.valid_from {
        vc["validFrom"] = json!(from);
    }
    if let Some(until) = &ica.valid_until {
        vc["validUntil"] = json!(until);
    }
    if let Value::Object(extra) = &ica.extra {
        for (k, v) in extra {
            vc[k] = v.clone();
        }
    }
    let mut protected = HeaderBuilder::new().algorithm(ica.alg);
    if let Some(cty) = ica.content_type {
        protected = protected.content_type(cty.to_owned());
    }
    let mut error = None;
    let sign1 = CoseSign1Builder::new()
        .protected(protected.build())
        .payload(serde_json::to_vec(&vc)?)
        .create_signature(b"", |data| {
            ica.issuer.sign(data).unwrap_or_else(|e| {
                error = Some(e);
                vec![]
            })
        })
        .build();
    if let Some(e) = error {
        return Err(e);
    }
    sign1.to_tagged_vec().map_err(|e| anyhow!("{e:?}"))
}

struct Dynamic(Arc<Identity>);

impl DynamicAssertion for Dynamic {
    fn label(&self) -> String {
        "cawg.identity".to_owned()
    }

    fn reserve_size(&self) -> c2pa::Result<usize> {
        Ok(self.0.reserve())
    }

    fn content(&self, _label: &str, size: Option<usize>, claim: &PartialClaim) -> c2pa::Result<DynamicAssertionContent> {
        self.0
            .content(size, claim)
            .map(DynamicAssertionContent::Cbor)
            .map_err(|e| c2pa::Error::BadParam(format!("{e:#}")))
    }
}

/// The C2PA claim signer, adding the identity assertions to the claim it signs.
pub struct ClaimSigner {
    pub inner: BoxedSigner,
    pub identities: Vec<Arc<Identity>>,
}

impl Signer for ClaimSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        self.inner.sign(data)
    }

    fn alg(&self) -> SigningAlg {
        self.inner.alg()
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        self.inner.certs()
    }

    fn reserve_size(&self) -> usize {
        self.inner.reserve_size()
    }

    fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
        self.identities.iter().map(|i| Box::new(Dynamic(i.clone())) as Box<dyn DynamicAssertion>).collect()
    }
}


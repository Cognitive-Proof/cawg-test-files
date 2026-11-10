//! Test credentials for the identity assertions: an X.509 CAWG test root with end-entity
//! certificates for named actors, and Ed25519 keys for identity claims aggregation issuers.
//!
//! Everything is created on the first run and kept under `credentials/`, so the trust settings
//! stay the same between runs. Delete the folder to mint new ones. None of it is secret: these
//! keys sign test files only.

use std::{fs, path::{Path, PathBuf}};

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use c2pa::SigningAlg;
use openssl::{
    asn1::{Asn1Integer, Asn1Object, Asn1OctetString, Asn1Time},
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private},
    sign::Signer,
    x509::{
        extension::{AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier},
        X509Builder, X509Extension, X509NameBuilder, X509,
    },
};

pub const EKU_DOCUMENT_SIGNING: &str = "1.3.6.1.5.5.7.3.36";
/// S/MIME Organization-validated Multipurpose: accepted by the CAWG interim trust model.
pub const POLICY_SMIME_ORG_MULTIPURPOSE: &str = "2.23.140.1.5.2.2";
/// S/MIME Mailbox-validated Multipurpose: excluded by the CAWG interim trust model.
pub const POLICY_SMIME_MAILBOX_MULTIPURPOSE: &str = "2.23.140.1.5.1.2";

/// 2020-01-01T00:00:00Z
const T2020: i64 = 1_577_836_800;
/// 2021-01-01T00:00:00Z
const T2021: i64 = 1_609_459_200;
/// 2026-01-01T00:00:00Z
const T2026: i64 = 1_767_225_600;
/// 2036-01-01T00:00:00Z
const T2036: i64 = 2_082_758_400;
/// 2040-01-01T00:00:00Z
const T2040: i64 = 2_208_988_800;

pub enum Eku {
    DocumentSigning,
    EmailProtection,
}

/// An end-entity X.509 credential: the `x5chain` (leaf first, DER) and its PEM private key.
pub struct Leaf {
    pub chain: Vec<Vec<u8>>,
    pub key_pem: Vec<u8>,
    pub alg: SigningAlg,
}

/// An identity claims aggregation issuer: an Ed25519 key and the `did:jwk` that names it.
pub struct IcaIssuer {
    key: PKey<Private>,
    pub did: String,
}

impl IcaIssuer {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(Signer::new_without_digest(&self.key)?.sign_oneshot_to_vec(data)?)
    }
}

pub struct Pki {
    dir: PathBuf,
    /// The CAWG trust anchor (`trust_kind: cawg`) the settings install.
    pub root: (X509, PKey<Private>),
    /// A CA that no trust list includes.
    pub rogue: (X509, PKey<Private>),
}

impl Pki {
    pub fn load_or_create(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let root = ca(dir, "cawg-test-root", "CAWG Test Root CA")?;
        let rogue = ca(dir, "rogue-root", "Untrusted Test Root CA")?;
        Ok(Self { dir: dir.to_owned(), root, rogue })
    }

    pub fn root_pem(&self) -> Result<String> {
        Ok(String::from_utf8(self.root.0.to_pem()?)?)
    }

    /// The end-entity certificate `name`, issued by `issuer` on first use.
    pub fn leaf(
        &self,
        name: &str,
        common_name: &str,
        issuer: &(X509, PKey<Private>),
        eku: Eku,
        policy: Option<&str>,
        validity: (i64, i64),
    ) -> Result<Leaf> {
        let (cert_path, key_path) = (self.dir.join(format!("{name}.pem")), self.dir.join(format!("{name}.key")));
        if !cert_path.exists() {
            let key = ec_key()?;
            let cert = issue(issuer, &key, common_name, eku, policy, validity)?;
            fs::write(&cert_path, cert.to_pem()?)?;
            fs::write(&key_path, key.private_key_to_pem_pkcs8()?)?;
        }
        let cert = X509::from_pem(&fs::read(&cert_path)?)?;
        Ok(Leaf { chain: vec![cert.to_der()?], key_pem: fs::read(&key_path)?, alg: SigningAlg::Es256 })
    }

    /// Valid from 2026 to 2036.
    pub fn current() -> (i64, i64) {
        (T2026, T2036)
    }

    /// Valid only during 2020.
    pub fn expired() -> (i64, i64) {
        (T2020, T2021)
    }

    /// The ICA issuer `name`, created on first use.
    pub fn ica_issuer(&self, name: &str) -> Result<IcaIssuer> {
        let path = self.dir.join(format!("{name}.key"));
        if !path.exists() {
            fs::write(&path, PKey::generate_ed25519()?.private_key_to_pem_pkcs8()?)?;
        }
        let key = PKey::private_key_from_pem(&fs::read(&path)?)?;
        anyhow::ensure!(key.id() == Id::ED25519, "{} is not an Ed25519 key", path.display());
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": B64URL.encode(key.raw_public_key()?),
        });
        let did = format!("did:jwk:{}", B64URL.encode(jwk.to_string()));
        Ok(IcaIssuer { key, did })
    }
}

fn ec_key() -> Result<PKey<Private>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    Ok(PKey::from_ec_key(EcKey::generate(&group)?)?)
}

fn serial() -> Result<Asn1Integer> {
    let mut bn = BigNum::new()?;
    bn.rand(126, MsbOption::MAYBE_ZERO, false)?;
    Ok(bn.to_asn1_integer()?)
}

/// A self-signed CA, created on first use.
fn ca(dir: &Path, name: &str, common_name: &str) -> Result<(X509, PKey<Private>)> {
    let (cert_path, key_path) = (dir.join(format!("{name}.pem")), dir.join(format!("{name}.key")));
    if !cert_path.exists() {
        let key = ec_key()?;
        let mut subject = X509NameBuilder::new()?;
        subject.append_entry_by_text("O", "CAWG Test Files (FOR TESTING ONLY)")?;
        subject.append_entry_by_text("CN", common_name)?;
        let subject = subject.build();
        let mut b = X509Builder::new()?;
        b.set_version(2)?;
        b.set_serial_number(&*serial()?)?;
        b.set_subject_name(&subject)?;
        b.set_issuer_name(&subject)?;
        b.set_pubkey(&key)?;
        b.set_not_before(&*Asn1Time::from_unix(T2020)?)?;
        b.set_not_after(&*Asn1Time::from_unix(T2040)?)?;
        b.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        b.append_extension(KeyUsage::new().critical().key_cert_sign().crl_sign().build()?)?;
        let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(None, None))?;
        b.append_extension(ski)?;
        b.sign(&key, MessageDigest::sha256())?;
        fs::write(&cert_path, b.build().to_pem()?)?;
        fs::write(&key_path, key.private_key_to_pem_pkcs8()?)?;
    }
    let cert = X509::from_pem(&fs::read(&cert_path)?).with_context(|| cert_path.display().to_string())?;
    let key = PKey::private_key_from_pem(&fs::read(&key_path)?)?;
    Ok((cert, key))
}

fn issue(
    (ca_cert, ca_key): &(X509, PKey<Private>),
    key: &PKey<Private>,
    common_name: &str,
    eku: Eku,
    policy: Option<&str>,
    (not_before, not_after): (i64, i64),
) -> Result<X509> {
    let mut subject = X509NameBuilder::new()?;
    subject.append_entry_by_text("O", "CAWG Test Files Named Actor")?;
    subject.append_entry_by_text("CN", common_name)?;
    let subject = subject.build();
    let mut b = X509Builder::new()?;
    b.set_version(2)?;
    b.set_serial_number(&*serial()?)?;
    b.set_subject_name(&subject)?;
    b.set_issuer_name(ca_cert.subject_name())?;
    b.set_pubkey(key)?;
    b.set_not_before(&*Asn1Time::from_unix(not_before)?)?;
    b.set_not_after(&*Asn1Time::from_unix(not_after)?)?;
    b.append_extension(BasicConstraints::new().critical().build()?)?;
    b.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    b.append_extension(
        match eku {
            Eku::DocumentSigning => ExtendedKeyUsage::new().other(EKU_DOCUMENT_SIGNING).build(),
            Eku::EmailProtection => ExtendedKeyUsage::new().email_protection().build(),
        }?,
    )?;
    if let Some(oid) = policy {
        b.append_extension(certificate_policies(oid)?)?;
    }
    let ski = SubjectKeyIdentifier::new().build(&b.x509v3_context(Some(ca_cert), None))?;
    b.append_extension(ski)?;
    let aki = AuthorityKeyIdentifier::new().keyid(false).build(&b.x509v3_context(Some(ca_cert), None))?;
    b.append_extension(aki)?;
    b.sign(ca_key, MessageDigest::sha256())?;
    Ok(b.build())
}

/// `certificatePolicies` with a single policy and no qualifiers.
fn certificate_policies(oid: &str) -> Result<X509Extension> {
    let policy_oid = Asn1Object::from_str(oid)?;
    let value = der_sequence(&der_sequence(&der_oid(policy_oid.as_slice())));
    let octets = Asn1OctetString::new_from_bytes(&value)?;
    Ok(X509Extension::new_from_der(&*Asn1Object::from_str("2.5.29.32")?, false, &octets)?)
}

fn der_oid(body: &[u8]) -> Vec<u8> {
    let mut der = vec![0x06, body.len() as u8];
    der.extend(body);
    der
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    let mut der = vec![0x30, content.len() as u8];
    der.extend(content);
    der
}

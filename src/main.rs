//! Generates the CAWG test set under `files/` and checks every file against its label.
//!
//! Run with `cargo run --release`. The run fails if the SDK's report on any file disagrees
//! with its label, or if the lint finds a problem in a file that should have none (or not
//! exactly the one an invalid fixture is for), so `labels.json` always matches the files.

mod identity;
mod lint;
mod pki;
mod sources;

use std::{
    fs::{self, File},
    io::Cursor,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context as _, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use c2pa::{Builder, Context, HashedUri, Reader, Settings, SigningAlg};
use identity::{ClaimSigner, Credential, Defect, Ica, Identity};
use pki::{Eku, IcaIssuer, Leaf, Pki};
use serde_json::{json, Value};

const GENERATOR: &str = "cawg-testfiles";
const IPTC: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/";

/// What a validator should conclude about one identity assertion (CAWG Identity 1.3 §7.2).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Outcome {
    /// `cawg.identity.trusted`
    Trusted,
    /// `cawg.identity.well-formed`
    WellFormed,
    /// Neither: validation reported a failure.
    Invalid,
}

impl Outcome {
    fn code(self) -> Option<&'static str> {
        match self {
            Outcome::Trusted => Some("cawg.identity.trusted"),
            Outcome::WellFormed => Some("cawg.identity.well-formed"),
            Outcome::Invalid => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Outcome::Trusted => "trusted",
            Outcome::WellFormed => "well-formed",
            Outcome::Invalid => "invalid",
        }
    }
}

/// The C2PA content of a case, apart from its identity assertions.
#[derive(Default)]
struct Content {
    /// Opened and cropped from this parent; otherwise a camera capture.
    parent: Option<PathBuf>,
    metadata: Option<Value>,
    /// Write `metadata` as a CBOR assertion instead of JSON.
    metadata_as_cbor: bool,
    training_mining: Option<Value>,
}

struct Case {
    category: &'static str,
    name: &'static str,
    description: &'static str,
    identities: Vec<Identity>,
    content: Content,
    /// One per identity assertion, in claim order.
    outcomes: Vec<Outcome>,
    /// Status codes the file must report for its identity assertions.
    codes: Vec<&'static str>,
    /// Text the file's only lint message must contain.
    lint: Option<&'static str>,
}

impl Case {
    fn new(category: &'static str, name: &'static str, description: &'static str) -> Self {
        Self {
            category,
            name,
            description,
            identities: vec![],
            content: Content::default(),
            outcomes: vec![],
            codes: vec![],
            lint: None,
        }
    }

    fn identity(mut self, identity: Identity, outcome: Outcome) -> Self {
        self.identities.push(identity);
        self.outcomes.push(outcome);
        self
    }

    fn codes(mut self, codes: &[&'static str]) -> Self {
        self.codes = codes.to_vec();
        self
    }

    fn parent(mut self, path: &Path) -> Self {
        self.content.parent = Some(path.to_owned());
        self
    }

    fn metadata(mut self, v: Value) -> Self {
        self.content.metadata = Some(v);
        self
    }

    fn training_mining(mut self, v: Value) -> Self {
        self.content.training_mining = Some(v);
        self
    }

    fn lint(mut self, text: &'static str) -> Self {
        self.lint = Some(text);
        self
    }
}

struct Gen {
    root: PathBuf,
    build: PathBuf,
    ctx: Arc<Context>,
    /// Same settings with identity assertions left undecoded, for the lint.
    raw_ctx: Arc<Context>,
    claim_cert: Vec<u8>,
    claim_key: Vec<u8>,
    labels: Vec<Value>,
    failures: Vec<String>,
}

impl Gen {
    fn out(&self, category: &str, name: &str) -> PathBuf {
        self.root.join("files").join(category).join(format!("{name}.jpg"))
    }

    fn src(&self, name: &str) -> PathBuf {
        self.build.join(name)
    }

    fn sign(&mut self, case: Case) -> Result<PathBuf> {
        let out = self.out(case.category, case.name);
        fs::create_dir_all(out.parent().unwrap())?;
        let title = out.file_name().unwrap().to_string_lossy().into_owned();
        let mut builder = Builder::from_shared_context(&self.ctx).with_definition(
            json!({
                "title": title,
                "format": "image/jpeg",
                "claim_generator_info": [{ "name": GENERATOR, "version": env!("CARGO_PKG_VERSION") }],
            })
            .to_string(),
        )?;
        let src = match &case.content.parent {
            Some(parent) => {
                builder.add_ingredient_from_stream(
                    json!({ "title": parent.file_name().unwrap().to_string_lossy(), "relationship": "parentOf", "label": "parent" })
                        .to_string(),
                    "image/jpeg",
                    &mut File::open(parent)?,
                )?;
                builder.add_assertion("c2pa.actions.v2", &json!({
                    "actions": [
                        { "action": "c2pa.opened", "parameters": { "ingredientIds": ["parent"] } },
                        { "action": "c2pa.cropped", "softwareAgent": { "name": "Northwind Photo Editor", "version": "12.3" } },
                    ],
                    "allActionsIncluded": true,
                }))?;
                self.src("photo-cropped.jpg")
            }
            None => {
                builder.add_assertion("c2pa.actions.v2", &json!({
                    "actions": [{
                        "action": "c2pa.created",
                        "digitalSourceType": format!("{IPTC}digitalCapture"),
                        "softwareAgent": { "name": "Northwind Camera Firmware", "version": "2.0.1" },
                    }],
                    "allActionsIncluded": true,
                }))?;
                self.src("photo.jpg")
            }
        };
        if let Some(m) = &case.content.metadata {
            if case.content.metadata_as_cbor {
                builder.add_assertion("cawg.metadata", m)?;
            } else {
                builder.add_assertion_json("cawg.metadata", m)?;
            }
        }
        if let Some(t) = &case.content.training_mining {
            builder.add_assertion("cawg.training-mining", t)?;
        }
        let signer = ClaimSigner {
            inner: c2pa::create_signer::from_keys(&self.claim_cert, &self.claim_key, SigningAlg::Ps256, None)?,
            identities: case.identities.into_iter().map(Arc::new).collect(),
        };
        let mut dest = Cursor::new(Vec::new());
        builder
            .sign(&signer, "image/jpeg", &mut File::open(&src)?, &mut dest)
            .with_context(|| format!("signing {}", out.display()))?;
        fs::write(&out, dest.into_inner())?;

        let report = self.check(&out, &case.outcomes, &case.codes, case.lint)?;
        self.labels.push(json!({
            "file": out.strip_prefix(&self.root)?.to_string_lossy(),
            "category": case.category,
            "description": case.description,
            "identityAssertions": report["identity"],
            "expectedStatusCodes": case.codes,
            "expectedLint": case.lint,
            "lint": report["lint"],
            "sdkValidationState": report["state"],
        }));
        Ok(out)
    }

    /// Reads `path` back and compares the SDK's report and the lint with the label.
    fn check(
        &mut self,
        path: &Path,
        outcomes: &[Outcome],
        codes: &[&str],
        expected_lint: Option<&str>,
    ) -> Result<Value> {
        let bytes = fs::read(path)?;
        let name = path.strip_prefix(&self.root)?.display().to_string();
        let reader = futures::executor::block_on(
            Reader::from_shared_context(&self.ctx).with_stream_async("image/jpeg", Cursor::new(&bytes)),
        )?;
        let statuses = reader
            .validation_results()
            .and_then(|r| r.active_manifest().cloned())
            .context("no validation results")?;
        let active = reader.active_label().context("no active manifest")?.to_owned();
        let mut identity = Vec::new();
        let mut seen: Vec<String> = Vec::new();
        for (i, expected) in outcomes.iter().enumerate() {
            let label = if i == 0 { "cawg.identity".to_owned() } else { format!("cawg.identity__{i}") };
            // Only this manifest's assertion: an ingredient's identity assertion has the same label.
            let suffix = format!("/c2pa/{active}/c2pa.assertions/{label}");
            let pick = |list: &[c2pa::validation_status::ValidationStatus]| -> Vec<String> {
                list.iter()
                    .filter(|s| s.url().is_some_and(|u| u.ends_with(&suffix)))
                    .map(|s| s.code().to_owned())
                    .collect()
            };
            let (success, info, failure) = (pick(statuses.success()), pick(statuses.informational()), pick(statuses.failure()));
            let actual = if success.iter().any(|c| c == "cawg.identity.trusted") {
                Outcome::Trusted
            } else if success.iter().any(|c| c == "cawg.identity.well-formed") {
                Outcome::WellFormed
            } else {
                Outcome::Invalid
            };
            if actual != *expected {
                self.failures.push(format!("{name} {label}: expected {}, SDK says {}", expected.name(), actual.name()));
            }
            if expected.code().is_some() && actual == *expected && !failure.is_empty() {
                // `cawg.x509.credential.untrusted` and `cawg.ica.untrusted_issuer` accompany
                // well-formed; nothing else may.
                let unexpected: Vec<_> = failure.iter().filter(|c| !c.ends_with("untrusted") && !c.ends_with("untrusted_issuer")).collect();
                if !unexpected.is_empty() {
                    self.failures.push(format!("{name} {label}: {} with failures {unexpected:?}", expected.name()));
                }
            }
            seen.extend(success.iter().chain(&info).chain(&failure).cloned());
            identity.push(json!({
                "label": label,
                "expectedOutcome": expected.name(),
                "sdkOutcome": actual.name(),
                "sdkStatus": { "success": success, "informational": info, "failure": failure },
            }));
        }
        for code in codes {
            if !seen.iter().any(|c| c == code) {
                self.failures.push(format!("{name}: expected status {code}, SDK reports {seen:?}"));
            }
        }

        let raw = futures::executor::block_on(
            Reader::from_shared_context(&self.raw_ctx).with_stream_async("image/jpeg", Cursor::new(&bytes)),
        )?;
        let lint = lint::lint(&serde_json::from_str(&raw.detailed_json())?, &serde_json::from_str(&raw.json())?);
        match expected_lint {
            None if !lint.is_empty() => self.failures.push(format!("{name}: lint {lint:?}")),
            Some(text) if lint.len() != 1 || !lint[0].contains(text) => {
                self.failures.push(format!("{name}: expected one lint message containing {text:?}, got {lint:?}"))
            }
            _ => {}
        }
        Ok(json!({ "identity": identity, "lint": lint, "state": format!("{:?}", reader.validation_state()) }))
    }
}

/// The claim signer's credentials and the CAWG trust configuration, layered over the C2PA
/// test settings: the CAWG test root as a `cawg` trust anchor and the trusted ICA issuer.
fn settings(root: &Path, pki: &Pki, trusted_issuer: &IcaIssuer) -> Result<Value> {
    let mut s: Value = serde_json::from_str(&fs::read_to_string(root.join("settings/c2pa-test-settings.json"))?)?;
    for auto in ["auto_created_action", "auto_opened_action", "auto_placed_action"] {
        s["builder"]["actions"][auto]["enabled"] = json!(false);
    }
    s["builder"]["claim_generator_info"] = json!({ "name": GENERATOR, "version": env!("CARGO_PKG_VERSION") });
    // Invalid identity assertions are the point of many cases; check by reading back instead.
    s["verify"]["verify_after_sign"] = json!(false);
    s["verify"]["remote_manifest_fetch"] = json!(false);
    let anchors = s["trust"]["anchors"].as_array_mut().context("no trust anchors")?;
    anchors.retain(|a| a["trust_kind"] != "cawg");
    anchors.push(json!({
        "trust_uri": "https://cawg-testfiles.example/trust/cawg-test-root",
        "trust_kind": "cawg",
        "trust_anchors": pki.root_pem()?,
        "trusted_ica_issuers": [trusted_issuer.did],
    }));
    Ok(s)
}

fn context(settings: &Value) -> Result<Arc<Context>> {
    Ok(Context::new().with_settings(Settings::new().with_json(&settings.to_string())?)?.into_shared())
}

/// The hashed URI of assertion `label` in the active manifest of `path`, absolute so that it
/// resolves from another claim.
fn assertion_ref(ctx: &Arc<Context>, path: &Path, label: &str) -> Result<HashedUri> {
    let reader = Reader::from_shared_context(ctx).with_file(path)?;
    let manifest = reader.active_label().context("no active manifest")?.to_owned();
    let detailed: Value = serde_json::from_str(&reader.detailed_json())?;
    let refs = detailed["manifests"][&manifest]["claim"]["created_assertions"]
        .as_array()
        .into_iter()
        .chain(detailed["manifests"][&manifest]["claim"]["assertions"].as_array())
        .flatten();
    let hash = refs
        .clone()
        .find(|a| a["url"].as_str().is_some_and(|u| u.ends_with(&format!("c2pa.assertions/{label}"))))
        .and_then(|a| a["hash"].as_str())
        .with_context(|| format!("{label} not in {}", path.display()))?;
    // `detailed_json` writes byte strings as `b64'…'`.
    let hash = hash.strip_prefix("b64'").and_then(|h| h.strip_suffix('\'')).unwrap_or(hash);
    let hash = BASE64.decode(hash).with_context(|| format!("hash {hash:?}"))?;
    Ok(HashedUri::new(format!("self#jumbf=/c2pa/{manifest}/c2pa.assertions/{label}"), None, &hash))
}

fn verified_identities() -> Value {
    let at = "2026-03-01T12:00:00Z";
    json!([
        {
            "type": "cawg.document_verification",
            "name": "Avery Quinn",
            "provider": { "id": "https://id-verify.example", "name": "Example ID Verification" },
            "verifiedAt": at,
        },
        {
            "type": "cawg.web_site",
            "uri": "https://averyquinn.example/",
            "provider": { "id": "https://domain-check.example", "name": "Example Domain Check" },
            "verifiedAt": at,
        },
        {
            "type": "cawg.affiliation",
            "name": "Northwind Traders",
            "provider": { "id": "https://northwindtraders.example", "name": "Northwind Traders" },
            "verifiedAt": at,
        },
        {
            "type": "cawg.social_media",
            "name": "Avery Quinn",
            "username": "averyquinn",
            "uri": "https://social.example/@averyquinn",
            "provider": { "id": "https://social.example", "name": "Example Social" },
            "verifiedAt": at,
        },
        {
            "type": "cawg.crypto_wallet",
            "address": "0x5a1fe5a1fe5a1fe5a1fe5a1fe5a1fe5a1fe5a1fe",
            "provider": { "id": "https://wallet.example", "name": "Example Wallet" },
            "verifiedAt": at,
        },
    ])
}

/// Removes the `verifiedIdentities` entry of `kind`'s field `field`.
fn without(mut identities: Value, kind: &str, field: &str) -> Value {
    for vi in identities.as_array_mut().unwrap() {
        if vi["type"] == kind {
            vi.as_object_mut().unwrap().remove(field);
        }
    }
    identities
}

fn iptc_metadata() -> Value {
    json!({
        "@context": {
            "dc": "http://purl.org/dc/elements/1.1/",
            "photoshop": "http://ns.adobe.com/photoshop/1.0/",
            "Iptc4xmpCore": "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/",
            "Iptc4xmpExt": "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
            "exif": "http://ns.adobe.com/exif/1.0/",
        },
        "dc:creator": ["Avery Quinn"],
        "dc:title": "Hills at dusk",
        "dc:rights": "© 2026 Northwind Traders. For testing only.",
        "photoshop:DateCreated": "2026-03-01",
        "photoshop:City": "Springfield",
        "Iptc4xmpCore:AltTextAccessibility": "Green hills under a blue sky.",
        "Iptc4xmpExt:PersonInImage": [],
        "exif:GPSLatitude": "39,47.6N",
        "exif:GPSLongitude": "89,38.7W",
    })
}

fn tdm(entries: Value) -> Value {
    json!({ "entries": entries })
}

fn all_tdm(use_: &str) -> Value {
    json!({
        "cawg.data_mining": { "use": use_ },
        "cawg.ai_inference": { "use": use_ },
        "cawg.ai_training": { "use": use_ },
        "cawg.ai_generative_training": { "use": use_ },
    })
}

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let build = root.join("target/sources");
    fs::create_dir_all(&build)?;
    let _ = fs::remove_dir_all(root.join("files"));

    let pki = Pki::load_or_create(&root.join("credentials"))?;
    let issuer = Arc::new(pki.ica_issuer("ica-issuer")?);
    let rogue_issuer = Arc::new(pki.ica_issuer("ica-rogue-issuer")?);
    let s = settings(&root, &pki, &issuer)?;
    fs::write(root.join("settings/cawg-test-settings.json"), serde_json::to_string_pretty(&s)? + "\n")?;
    let mut raw = s.clone();
    raw["core"]["decode_identity_assertions"] = json!(false);
    // The settings file stores PEM line breaks as `\n` escapes inside the JSON strings.
    let pem = |key: &str| -> Result<Vec<u8>> {
        Ok(s["signer"]["local"][key].as_str().context("no claim signer")?.replace("\\n", "\n").into_bytes())
    };
    let (claim_cert, claim_key) = (pem("sign_cert")?, pem("private_key")?);
    let mut g = Gen {
        root: root.clone(),
        build,
        ctx: context(&s)?,
        raw_ctx: context(&raw)?,
        claim_cert: claim_cert.clone(),
        claim_key: claim_key.clone(),
        labels: vec![],
        failures: vec![],
    };

    let photo = sources::photo(1);
    photo.save(g.src("photo.jpg"))?;
    sources::crop(&photo).save(g.src("photo-cropped.jpg"))?;

    // ---- credentials ----------------------------------------------------------------------
    let now = Pki::current();
    let creator = || pki.leaf("creator-document-signing", "Avery Quinn", &pki.root, Eku::DocumentSigning, None, now);
    let editor = || pki.leaf("editor-document-signing", "Jordan Lee", &pki.root, Eku::DocumentSigning, None, now);
    let publisher = || pki.leaf("publisher-document-signing", "Northwind Traders", &pki.root, Eku::DocumentSigning, None, now);
    let x509 = |leaf: Result<Leaf>| leaf.map(Credential::X509);
    let ica = |identities: Value| Credential::Ica(Ica::new(&issuer, identities));
    let actions = ["c2pa.actions.v2"];
    use Outcome::*;

    // ---- identity: trusted -----------------------------------------------------------------
    let t01 = g.sign(
        Case::new("identity/trusted", "t01_x509_creator", "Camera capture with an X.509 identity assertion (documentSigning EKU) naming its creator.")
            .identity(Identity::new(x509(creator())?, &["cawg.creator"], &actions), Trusted)
            .codes(&["cawg.x509.signature.validated", "cawg.x509.credential.trusted"]),
    )?;
    g.sign(
        Case::new("identity/trusted", "t02_x509_interim_smime", "Creator signs with an S/MIME certificate under the interim trust model: emailProtection EKU and the Organization-validated Multipurpose policy. Interim acceptance ends on 31 March 2027 for an assertion without a time stamp, so after that date this file becomes well-formed.")
            .identity(
                Identity::new(
                    x509(pki.leaf("creator-interim-smime", "Avery Quinn", &pki.root, Eku::EmailProtection, Some(pki::POLICY_SMIME_ORG_MULTIPURPOSE), now))?,
                    &["cawg.creator"],
                    &actions,
                ),
                Trusted,
            )
            .codes(&["cawg.x509.credential.trusted"]),
    )?;
    g.sign(
        Case::new("identity/trusted", "t03_x509_creator_and_editor", "Two identity assertions in one claim (cawg.identity and cawg.identity__1): a creator and an editor, each with its own certificate.")
            .identity(Identity::new(x509(creator())?, &["cawg.creator"], &actions), Trusted)
            .identity(Identity::new(x509(editor())?, &["cawg.editor"], &actions), Trusted),
    )?;
    let mut ingredient_editor = Identity::new(x509(editor())?, &["cawg.editor"], &actions);
    ingredient_editor.ingredient_references = vec![assertion_ref(&g.ctx, &t01, "c2pa.actions.v2")?];
    g.sign(
        Case::new("identity/trusted", "t04_x509_references_ingredient_claim", "t01 opened and cropped. The editor's identity assertion also references the c2pa.actions.v2 assertion in the parent's claim, which §5.1.1 allows.")
            .parent(&t01)
            .identity(ingredient_editor, Trusted),
    )?;
    g.sign(
        Case::new("identity/trusted", "t05_ica_verified_identities", "Identity claims aggregation credential from a trusted issuer (did:jwk) with one verified identity of each type: document verification, web site, affiliation, social media and crypto wallet.")
            .identity(Identity::new(ica(verified_identities()), &["cawg.creator"], &actions), Trusted)
            .codes(&["cawg.ica.credential_valid"]),
    )?;
    g.sign(
        Case::new("identity/trusted", "t06_x509_publisher_and_ica_creator", "A creator identified through identity claims aggregation and a publisher with its own X.509 certificate.")
            .identity(Identity::new(ica(verified_identities()), &["cawg.creator"], &actions), Trusted)
            .identity(Identity::new(x509(publisher())?, &["cawg.publisher"], &actions), Trusted),
    )?;
    g.sign(
        Case::new("identity/trusted", "t07_x509_custom_role", "A role outside the predefined list (com.northwind.colorist), which §5.1.2 allows with C2PA label syntax.")
            .identity(Identity::new(x509(editor())?, &["com.northwind.colorist"], &actions), Trusted),
    )?;
    g.sign(
        Case::new("identity/trusted", "t08_x509_no_role", "No role field: role is optional.")
            .identity(Identity::new(x509(creator())?, &[], &actions), Trusted),
    )?;
    g.sign(
        Case::new("identity/trusted", "t09_x509_hard_binding_only", "The identity assertion references only the hard binding, the minimum §5.1.1 allows.")
            .identity(Identity::new(x509(creator())?, &["cawg.creator"], &[]), Trusted),
    )?;

    // ---- identity: well-formed -------------------------------------------------------------
    g.sign(
        Case::new("identity/well-formed", "w01_x509_untrusted_root", "Valid X.509 identity signature whose certificate chains to a root on no trust list.")
            .identity(
                Identity::new(x509(pki.leaf("creator-untrusted-root", "Avery Quinn", &pki.rogue, Eku::DocumentSigning, None, now))?, &["cawg.creator"], &actions),
                WellFormed,
            )
            .codes(&["cawg.x509.signature.validated", "cawg.x509.credential.untrusted"]),
    )?;
    g.sign(
        Case::new("identity/well-formed", "w02_x509_interim_mailbox_policy", "S/MIME certificate with the Mailbox-validated Multipurpose policy, which the interim trust model excludes.")
            .identity(
                Identity::new(
                    x509(pki.leaf("creator-interim-mailbox", "Avery Quinn", &pki.root, Eku::EmailProtection, Some(pki::POLICY_SMIME_MAILBOX_MULTIPURPOSE), now))?,
                    &["cawg.creator"],
                    &actions,
                ),
                WellFormed,
            )
            .codes(&["cawg.x509.credential.untrusted"]),
    )?;
    g.sign(
        Case::new("identity/well-formed", "w03_x509_email_without_policy", "emailProtection certificate with no certificate policy, so the interim trust model doesn't apply.")
            .identity(
                Identity::new(x509(pki.leaf("creator-email-no-policy", "Avery Quinn", &pki.root, Eku::EmailProtection, None, now))?, &["cawg.creator"], &actions),
                WellFormed,
            )
            .codes(&["cawg.x509.credential.untrusted"]),
    )?;
    g.sign(
        Case::new("identity/well-formed", "w04_x509_c2pa_claim_signer_cert", "The identity assertion is signed with the C2PA claim signer's certificate. That root is a C2PA (manifest) trust anchor, not a CAWG one, so the named actor isn't trusted.")
            .identity(
                Identity::new(
                    Credential::X509(Leaf { chain: c2pa_chain(&claim_cert)?, key_pem: claim_key.clone(), alg: SigningAlg::Ps256 }),
                    &["cawg.creator"],
                    &actions,
                ),
                WellFormed,
            )
            .codes(&["cawg.x509.credential.untrusted"]),
    )?;
    g.sign(
        Case::new("identity/well-formed", "w05_ica_untrusted_issuer", "Valid identity claims aggregation credential from an issuer that isn't on the trusted issuer list.")
            .identity(Identity::new(Credential::Ica(Ica::new(&rogue_issuer, verified_identities())), &["cawg.creator"], &actions), WellFormed)
            .codes(&["cawg.ica.untrusted_issuer"]),
    )?;

    // ---- identity: invalid -----------------------------------------------------------------
    let bad = |defect: Defect| -> Result<Identity> { Ok(Identity::new(x509(creator())?, &["cawg.creator"], &actions).with(defect)) };
    let bad_ica = |defect: Defect| Identity::new(ica(verified_identities()), &["cawg.creator"], &actions).with(defect);
    let invalid = |name, description, identity, code| {
        Case::new("identity/invalid", name, description).identity(identity, Invalid).codes(&[code])
    };
    g.sign(invalid("x01_x509_signature_mismatch", "One bit of the X.509 COSE signature flipped.", bad(Defect::CorruptSignature)?, "cawg.x509.signature.mismatch"))?;
    g.sign(invalid("x02_x509_algorithm_unsupported", "COSE alg header set to RS256, which C2PA doesn't allow.", bad(Defect::UnsupportedAlgorithm)?, "cawg.x509.algorithm.unsupported"))?;
    g.sign(invalid(
        "x03_x509_certificate_expired",
        "Signed with a certificate that expired in 2021, with no time stamp.",
        Identity::new(x509(pki.leaf("creator-expired", "Avery Quinn", &pki.root, Eku::DocumentSigning, None, Pki::expired()))?, &["cawg.creator"], &actions),
        "cawg.x509.signature.outside_validity",
    ))?;
    g.sign(invalid("x04_x509_signed_different_payload", "The COSE signature covers a signer payload with fewer referenced assertions than the one in the assertion.", bad(Defect::SignedDifferentPayload)?, "cawg.x509.signature.mismatch"))?;
    g.sign(invalid("x05_hard_binding_missing", "referenced_assertions leaves out the claim's hard binding (c2pa.hash.data).", bad(Defect::NoHardBinding)?, "cawg.identity.hard_binding_missing"))?;
    let mut foreign = Identity::new(x509(editor())?, &["cawg.editor"], &actions);
    foreign.foreign_hard_binding = Some(assertion_ref(&g.ctx, &t01, "c2pa.hash.data")?);
    g.sign(
        invalid("x06_hard_binding_incorrect", "t01 opened and cropped; the identity assertion references the parent's c2pa.hash.data instead of its own claim's.", foreign, "cawg.identity.hard_binding_incorrect")
            .parent(&t01),
    )?;
    g.sign(invalid("x07_referenced_assertion_mismatch", "The hash of the referenced c2pa.actions.v2 doesn't match the claim's.", bad(Defect::StaleReference)?, "cawg.identity.assertion.mismatch"))?;
    g.sign(invalid("x08_referenced_assertion_duplicate", "c2pa.actions.v2 appears twice in referenced_assertions.", bad(Defect::DuplicateReference)?, "cawg.identity.assertion.duplicate"))?;
    g.sign(invalid("x09_pad_not_zero", "pad1 is filled with 0x01 bytes.", bad(Defect::NonZeroPad)?, "cawg.identity.pad.invalid"))?;
    g.sign(
        invalid("x10_signer_payload_missing", "The identity assertion has no signer_payload.", bad(Defect::MissingSignerPayload)?, "cawg.identity.cbor.invalid")
            .lint("signer_payload is missing"),
    )?;
    g.sign(
        invalid(
            "x11_role_empty_array",
            "role is an empty array; the CDDL requires at least one entry.",
            Identity::new(x509(creator())?, &[], &actions).with(Defect::EmptyRole),
            "cawg.identity.cbor.invalid",
        )
            .lint("role [] is not a non-empty array"),
    )?;
    g.sign(invalid(
        "x12_sig_type_unknown",
        "sig_type com.example.unknown-credential, which no validator recognises.",
        Identity::new(Credential::Unknown("com.example.unknown-credential"), &["cawg.creator"], &actions),
        "cawg.identity.sig_type.unknown",
    ))?;
    g.sign(invalid("x13_ica_signature_mismatch", "One bit of the ICA credential's COSE signature flipped.", bad_ica(Defect::CorruptSignature), "cawg.ica.signature_mismatch"))?;
    g.sign(invalid("x14_ica_signer_payload_mismatch", "The credential's c2paAsset has fewer referenced assertions than the assertion's signer_payload.", bad_ica(Defect::SignedDifferentPayload), "cawg.ica.signer_payload.mismatch"))?;
    let ica_with = |f: &dyn Fn(&mut Ica)| {
        let mut c = Ica::new(&issuer, verified_identities());
        f(&mut c);
        Identity::new(Credential::Ica(c), &["cawg.creator"], &actions)
    };
    g.sign(invalid("x15_ica_content_type_missing", "The ICA COSE_Sign1 has no content type header (application/vc is required).", ica_with(&|c| c.content_type = None), "cawg.ica.invalid_content_type"))?;
    g.sign(invalid("x16_ica_valid_from_missing", "The credential has no validFrom.", ica_with(&|c| c.valid_from = None), "cawg.ica.valid_from.missing"))?;
    g.sign(invalid("x17_ica_valid_until_past", "The credential's validUntil is in 2025.", ica_with(&|c| c.valid_until = Some("2025-12-31T23:59:59Z".into())), "cawg.ica.valid_until.invalid"))?;
    g.sign(invalid("x18_ica_verified_identities_empty", "verifiedIdentities is an empty array.", ica_with(&|c| c.identities = json!([])), "cawg.ica.verified_identities.missing"))?;
    g.sign(invalid(
        "x19_ica_crypto_wallet_without_address",
        "A cawg.crypto_wallet verified identity without address (§8.1.2.5 requires it).",
        ica_with(&|c| c.identities = without(verified_identities(), "cawg.crypto_wallet", "address")),
        "cawg.ica.verified_identities.invalid",
    ))?;
    g.sign(invalid(
        "x20_ica_social_media_without_username",
        "A cawg.social_media verified identity without username (§8.1.2.5 requires it).",
        ica_with(&|c| c.identities = without(verified_identities(), "cawg.social_media", "username")),
        "cawg.ica.verified_identities.invalid",
    ))?;
    g.sign(invalid(
        "x21_ica_revocation_unsupported",
        "The credential has a credentialStatus entry of a type the validator doesn't support.",
        ica_with(&|c| {
            c.extra = json!({ "credentialStatus": {
                "id": "https://status.example/credentials/3#94567",
                "type": "ExampleRevocationList2026",
                "statusPurpose": "revocation",
            }})
        }),
        "cawg.ica.revocation.unsupported",
    ))?;
    g.sign(invalid(
        "x22_ica_did_method_unsupported",
        "The credential's issuer is a did:example DID, a method the validator can't resolve.",
        ica_with(&|c| c.issuer_did = Some("did:example:northwind-identity-aggregator".into())),
        "cawg.ica.did_unsupported_method",
    ))?;

    // ---- metadata -------------------------------------------------------------------------
    let creator_of = |labels: &[&'static str]| -> Result<Identity> { Ok(Identity::new(x509(creator())?, &["cawg.creator"], labels)) };
    let with_meta = ["c2pa.actions.v2", "cawg.metadata"];
    g.sign(
        Case::new("metadata/valid", "m01_iptc_photo_metadata", "cawg.metadata with Dublin Core, IPTC Core and Extension, Photoshop and EXIF fields, referenced by the creator's identity assertion.")
            .metadata(iptc_metadata())
            .identity(creator_of(&with_meta)?, Trusted),
    )?;
    g.sign(
        Case::new("metadata/valid", "m02_custom_namespace", "A namespace outside the C2PA metadata allow-list: the c2pa.metadata restrictions don't apply to cawg.metadata (§3).")
            .metadata(json!({
                "@context": { "dc": "http://purl.org/dc/elements/1.1/", "nw": "https://ns.northwindtraders.example/photo/1.0/" },
                "dc:creator": ["Avery Quinn"],
                "nw:assignment": "Spring landscapes",
                "nw:shotList": ["hills", "sky"],
            }))
            .identity(creator_of(&with_meta)?, Trusted),
    )?;
    g.sign(
        Case::new("metadata/valid", "m03_context_array", "@context as an array of an IRI and a term map, both of which JSON-LD allows.")
            .metadata(json!({
                "@context": ["https://schema.org/", { "dc": "http://purl.org/dc/elements/1.1/" }],
                "dc:title": "Hills at dusk",
                "name": "Hills at dusk",
            }))
            .identity(creator_of(&with_meta)?, Trusted),
    )?;
    let mut no_context = iptc_metadata();
    no_context.as_object_mut().unwrap().remove("@context");
    g.sign(
        Case::new("metadata/invalid", "mx01_context_missing", "cawg.metadata without @context (§3 requires it).")
            .metadata(no_context)
            .identity(creator_of(&with_meta)?, Trusted)
            .lint("@context is missing"),
    )?;
    let mut undefined_prefix = iptc_metadata();
    undefined_prefix["xmpRights:UsageTerms"] = json!("For testing only");
    g.sign(
        Case::new("metadata/invalid", "mx02_prefix_not_in_context", "xmpRights:UsageTerms uses a prefix @context doesn't define, so JSON-LD expansion drops the field.")
            .metadata(undefined_prefix)
            .identity(creator_of(&with_meta)?, Trusted)
            .lint("xmpRights:UsageTerms uses prefix xmpRights"),
    )?;
    let mut cbor = Case::new("metadata/invalid", "mx03_cbor_box", "cawg.metadata stored as a CBOR assertion; §3 requires a JSON content type box.")
        .metadata(iptc_metadata())
        .identity(creator_of(&with_meta)?, Trusted)
        .lint("not in a JSON content type box");
    cbor.content.metadata_as_cbor = true;
    g.sign(cbor)?;

    // ---- training and data mining ---------------------------------------------------------
    let with_tdm = ["c2pa.actions.v2", "cawg.training-mining"];
    g.sign(
        Case::new("training-mining/valid", "tm01_all_not_allowed", "All four standard entries notAllowed, referenced by the creator's identity assertion.")
            .training_mining(tdm(all_tdm("notAllowed")))
            .identity(creator_of(&with_tdm)?, Trusted),
    )?;
    let mut constrained = all_tdm("allowed");
    constrained["cawg.ai_generative_training"] = json!({ "use": "constrained", "constraint_info": "https://northwindtraders.example/licensing/ai" });
    constrained["cawg.ai_training"] = json!({ "use": "constrained" });
    g.sign(
        Case::new("training-mining/valid", "tm02_constrained", "Generative training constrained with a licence URL; AI training constrained with no constraint_info, which §3 says to treat as notAllowed; the rest allowed.")
            .training_mining(tdm(constrained))
            .identity(creator_of(&with_tdm)?, Trusted),
    )?;
    let mut custom = all_tdm("notAllowed");
    custom["com.northwind.style_transfer"] = json!({ "use": "allowed" });
    g.sign(
        Case::new("training-mining/valid", "tm03_custom_entry", "An entity-specific entry (com.northwind.style_transfer) next to the standard ones.")
            .training_mining(tdm(custom))
            .identity(creator_of(&with_tdm)?, Trusted),
    )?;
    g.sign(
        Case::new("training-mining/valid", "tm04_with_metadata", "Entries plus the optional metadata map, with no identity assertion.")
            .training_mining(json!({ "entries": all_tdm("notAllowed"), "metadata": { "reviewer": "Northwind Rights Desk" } })),
    )?;
    let tdm_invalid = |name, description, v: Value, lint| {
        Ok::<_, anyhow::Error>(
            Case::new("training-mining/invalid", name, description).training_mining(v).identity(creator_of(&with_tdm)?, Trusted).lint(lint),
        )
    };
    g.sign(tdm_invalid("tmx01_entries_missing", "No entries map (§3.2 requires it).", json!({ "metadata": {} }), "entries is missing")?)?;
    let mut bad_use = all_tdm("notAllowed");
    bad_use["cawg.ai_training"] = json!({ "use": "prohibited" });
    g.sign(tdm_invalid("tmx02_use_not_in_choice", "use \"prohibited\" isn't one of allowed, notAllowed or constrained.", tdm(bad_use), "is not allowed, notAllowed or constrained")?)?;
    let mut reserved = all_tdm("notAllowed");
    reserved["cawg.ai_fine_tuning"] = json!({ "use": "notAllowed" });
    g.sign(tdm_invalid("tmx03_reserved_prefix", "cawg.ai_fine_tuning: the cawg. prefix is reserved for the standard entries.", tdm(reserved), "reserved cawg. prefix")?)?;
    let mut empty_info = all_tdm("notAllowed");
    empty_info["cawg.ai_training"] = json!({ "use": "constrained", "constraint_info": "" });
    g.sign(tdm_invalid("tmx04_constraint_info_empty", "constraint_info is an empty string; the CDDL requires at least one character.", tdm(empty_info), "constraint_info \"\" is not a non-empty text string")?)?;
    let mut no_use = all_tdm("notAllowed");
    no_use["cawg.data_mining"] = json!({ "constraint_info": "Ask first" });
    g.sign(tdm_invalid("tmx05_use_missing", "An entry with constraint_info but no use.", tdm(no_use), "has no use")?)?;
    let mut bad_custom = all_tdm("notAllowed");
    bad_custom["StyleTransfer"] = json!({ "use": "allowed" });
    g.sign(tdm_invalid("tmx06_custom_key_not_a_label", "Custom entry key StyleTransfer doesn't follow the C2PA custom label syntax.", tdm(bad_custom), "isn't a valid custom label")?)?;

    fs::write(root.join("labels.json"), serde_json::to_string_pretty(&g.labels)? + "\n")?;
    println!("{} files written", g.labels.len());
    if !g.failures.is_empty() {
        for f in &g.failures {
            eprintln!("FAIL {f}");
        }
        bail!("{} check(s) failed", g.failures.len());
    }
    Ok(())
}

/// The claim signer's PEM chain as DER, for reuse as an identity credential.
fn c2pa_chain(pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(openssl::x509::X509::stack_from_pem(pem)?.iter().map(|c| c.to_der()).collect::<Result<_, _>>()?)
}

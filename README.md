# CAWG test files

C2PA-signed JPEGs for the three Creator Assertions Working Group specifications:

- [Identity Assertion 1.3](https://cawg.io/identity/1.3/) (`cawg.identity`), with both credential
  types: X.509 certificates (`cawg.x509.cose`) and identity claims aggregation
  (`cawg.identity_claims_aggregation`, a W3C verifiable credential from an identity aggregator).
- [Metadata Assertion 1.1](https://cawg.io/metadata/1.1/) (`cawg.metadata`).
- [Training and Data Mining Assertion 1.1](https://cawg.io/training-and-data-mining/1.1/)
  (`cawg.training-mining`).

Built the same way as c2pa-ai-examples: a Rust generator signs every file,
reads it back, and fails if any file doesn't match its label.

| Folder | What a validator should conclude |
|---|---|
| [`files/identity/trusted/`](files/identity/trusted) | Every identity assertion validates and its named actor has a root of trust: `cawg.identity.trusted` (§7.2). |
| [`files/identity/well-formed/`](files/identity/well-formed) | The identity assertion validates, but no root of trust was found for the named actor: `cawg.identity.well-formed`. |
| [`files/identity/invalid/`](files/identity/invalid) | The identity assertion fails validation with one specific status code. Neither `trusted` nor `well-formed` may be reported. |
| [`files/metadata/valid/`](files/metadata/valid), [`invalid/`](files/metadata/invalid) | `cawg.metadata` that meets §3, or breaks one rule. |
| [`files/training-mining/valid/`](files/training-mining/valid), [`invalid/`](files/training-mining/invalid) | `cawg.training-mining` that meets the §3.2 CDDL and label rules, or breaks one. |

The metadata and training-and-data-mining files also carry a trusted creator identity assertion
that references the CAWG assertion, the way the specifications expect them to be used. The SDK
doesn't validate either assertion type, so their verdicts come from this repository's schema lint
(see [Schema checks](#schema-checks)).

[`labels.json`](labels.json) records, for every file, the expected outcome of each identity
assertion, the status codes it must report, the expected lint message, and what c2pa-rs actually
reported.

All media is procedural (a synthetic landscape); every named person and organisation is fictitious.

## The cases

| File | What it tests |
|---|---|
| **identity/trusted** | |
| `t01_x509_creator` | Camera capture with an X.509 identity assertion naming its creator. The certificate has the `id-kp-documentSigning` EKU and chains to the CAWG test root. |
| `t02_x509_interim_smime` | Interim trust model (§8.2.4): `emailProtection` EKU and the S/MIME Organization-validated Multipurpose policy (2.23.140.1.5.2.2). **Expires:** without a time stamp the interim rules only apply until 31 March 2027, after which this file reads as well-formed. |
| `t03_x509_creator_and_editor` | Two identity assertions in one claim (`cawg.identity`, `cawg.identity__1`), each with its own certificate and role. |
| `t04_x509_references_ingredient_claim` | t01 opened and cropped. The editor's assertion also references `c2pa.actions.v2` in the parent's claim, which §5.1.1 allows. |
| `t05_ica_verified_identities` | Identity claims aggregation from a trusted `did:jwk` issuer, with one verified identity of each type: document verification, web site, affiliation, social media, crypto wallet. |
| `t06_x509_publisher_and_ica_creator` | An ICA creator and an X.509 publisher in the same claim. |
| `t07_x509_custom_role` | Role `com.northwind.colorist`, outside the predefined list. |
| `t08_x509_no_role` | No `role` field: it's optional. |
| `t09_x509_hard_binding_only` | References only the hard binding, the minimum allowed. |
| **identity/well-formed** | |
| `w01_x509_untrusted_root` | Certificate from a CA that's on no trust list: `cawg.x509.credential.untrusted`. |
| `w02_x509_interim_mailbox_policy` | S/MIME Mailbox-validated policy, which the interim model excludes. |
| `w03_x509_email_without_policy` | `emailProtection` with no certificate policy. |
| `w04_x509_c2pa_claim_signer_cert` | Identity signed with the C2PA claim signer's certificate. A C2PA (manifest) trust anchor doesn't make an identity trusted; CAWG anchors are separate. |
| `w05_ica_untrusted_issuer` | Valid credential from an issuer that isn't on the trusted-issuer list: `cawg.ica.untrusted_issuer`. |
| **identity/invalid** | |
| `x01_x509_signature_mismatch` | A bit of the COSE signature flipped: `cawg.x509.signature.mismatch`. |
| `x02_x509_algorithm_unsupported` | COSE `alg` set to RS256: `cawg.x509.algorithm.unsupported`. |
| `x03_x509_certificate_expired` | Certificate expired in 2021, no time stamp: `cawg.x509.signature.outside_validity`. |
| `x04_x509_signed_different_payload` | The signature covers fewer referenced assertions than the assertion lists: `cawg.x509.signature.mismatch`. |
| `x05_hard_binding_missing` | `c2pa.hash.data` not referenced: `cawg.identity.hard_binding_missing`. |
| `x06_hard_binding_incorrect` | References the parent's `c2pa.hash.data` instead of its own: `cawg.identity.hard_binding_incorrect`. |
| `x07_referenced_assertion_mismatch` | A referenced assertion's hash doesn't match the claim: `cawg.identity.assertion.mismatch`. |
| `x08_referenced_assertion_duplicate` | `c2pa.actions.v2` referenced twice: `cawg.identity.assertion.duplicate`. |
| `x09_pad_not_zero` | `pad1` filled with 0x01: `cawg.identity.pad.invalid`. |
| `x10_signer_payload_missing` | No `signer_payload`: `cawg.identity.cbor.invalid`. |
| `x11_role_empty_array` | `role: []`; the CDDL needs at least one entry: `cawg.identity.cbor.invalid`. |
| `x12_sig_type_unknown` | `sig_type` no validator knows: `cawg.identity.sig_type.unknown`. |
| `x13_ica_signature_mismatch` | ICA COSE signature corrupted: `cawg.ica.signature_mismatch`. |
| `x14_ica_signer_payload_mismatch` | The credential's `c2paAsset` covers fewer assertions than `signer_payload`: `cawg.ica.signer_payload.mismatch`. |
| `x15_ica_content_type_missing` | No `application/vc` content type header: `cawg.ica.invalid_content_type`. |
| `x16_ica_valid_from_missing` | No `validFrom`: `cawg.ica.valid_from.missing`. |
| `x17_ica_valid_until_past` | `validUntil` in 2025: `cawg.ica.valid_until.invalid`. |
| `x18_ica_verified_identities_empty` | `verifiedIdentities: []`: `cawg.ica.verified_identities.missing`. |
| `x19_ica_crypto_wallet_without_address` | `cawg.crypto_wallet` without `address`: `cawg.ica.verified_identities.invalid`. |
| `x20_ica_social_media_without_username` | `cawg.social_media` without `username`: `cawg.ica.verified_identities.invalid`. |
| `x21_ica_revocation_unsupported` | A `credentialStatus` of an unsupported type: `cawg.ica.revocation.unsupported`. |
| `x22_ica_did_method_unsupported` | Issuer `did:example:…`: `cawg.ica.did_unsupported_method`. |
| **metadata/valid** | |
| `m01_iptc_photo_metadata` | Dublin Core, IPTC Core and Extension, Photoshop and EXIF fields. |
| `m02_custom_namespace` | A namespace outside the C2PA metadata allow-list, which §3 says doesn't apply to `cawg.metadata`. |
| `m03_context_array` | `@context` as an array of an IRI and a term map, as JSON-LD allows. |
| **metadata/invalid** | |
| `mx01_context_missing` | No `@context` (§3 requires it). |
| `mx02_prefix_not_in_context` | `xmpRights:UsageTerms` with no `xmpRights` prefix in `@context`, so JSON-LD expansion drops it. |
| `mx03_cbor_box` | Stored as CBOR; §3 requires a JSON content type box. |
| **training-mining/valid** | |
| `tm01_all_not_allowed` | All four standard entries `notAllowed`. |
| `tm02_constrained` | `constrained` with a licence URL, and `constrained` with no `constraint_info` (which §3 says to treat as `notAllowed`). |
| `tm03_custom_entry` | An entity-specific entry next to the standard ones. |
| `tm04_with_metadata` | The optional `metadata` map; no identity assertion. |
| **training-mining/invalid** | |
| `tmx01_entries_missing` | No `entries`. |
| `tmx02_use_not_in_choice` | `use: "prohibited"`. |
| `tmx03_reserved_prefix` | `cawg.ai_fine_tuning`: the `cawg.` prefix is reserved for the standard entries. |
| `tmx04_constraint_info_empty` | `constraint_info: ""`. |
| `tmx05_use_missing` | An entry with no `use`. |
| `tmx06_custom_key_not_a_label` | Custom key `StyleTransfer` doesn't follow the C2PA label syntax. |

## Trust

Everything is test-only. Don't use these files to test real-world trust decisions.

- **C2PA claim signer:** the public C2PA test certificate from c2pa-rs, as in c2pa-ai-examples.
- **X.509 identities:** end-entity certificates from a *CAWG Test Root CA* minted by the generator.
  A second, *Untrusted Test Root CA* issues w01's certificate.
- **ICA issuers:** two Ed25519 keys, named by `did:jwk` DIDs: one trusted, one not (w05).

The generator creates these on first run and keeps them in [`credentials/`](credentials) so that
the trust configuration stays stable. Delete that folder to mint new ones. The private keys are
committed on purpose: they only sign test files.

[`settings/cawg-test-settings.json`](settings/cawg-test-settings.json) is the c2pa-rs settings
file the check uses: the C2PA test trust anchors, the CAWG test root as a `cawg` trust anchor, and
the trusted ICA issuer in `trusted_ica_issuers`. Validators without those settings report every
identity as untrusted. Current c2pa-rs releases (and c2patool 0.27.22) can't resolve these
`did:jwk` issuers at all and report `cawg.ica.invalid_did_document` (see below).

## Schema checks

The SDK doesn't validate `cawg.metadata` or `cawg.training-mining`, so
[`src/lint.rs`](src/lint.rs) checks them against the specifications:

- **`cawg.metadata` (§3):** it's in a JSON content type box, it's a JSON object with `@context`, and
  every compact IRI (`prefix:term`) uses a prefix that `@context` defines.
- **`cawg.training-mining` (§3.2):** `entries` is present and is a map. Each entry has a `use` of
  `allowed`, `notAllowed` or `constrained`, and `constraint_info`, if present, is a non-empty
  string. `cawg.`-prefixed keys are only the four standard ones; other keys follow the C2PA
  custom label syntax.
- **`cawg.identity` (§5.2 CDDL):** the field set, byte strings, a non-empty
  `referenced_assertions` of hashed URIs, a non-empty `sig_type`, and a `role` that is absent or a
  non-empty array of non-empty strings. It reads the raw assertions with
  `core.decode_identity_assertions` off.

Every valid file must lint clean. Every file in an `invalid/` folder must produce exactly one lint
message, the one it was built for. For identity cases, the SDK's status codes are the main check;
the lint catches the two CDDL cases, x10 and x11.

The training-and-data-mining 1.1 prose spells the field `constraints_info`, but its CDDL and
example use `constraint_info`. These files follow the CDDL.

## c2pa-rs changes

The generator builds against `../c2pa-rs-cawg-testfiles`, a worktree of the local c2pa-rs
checkout on branch **`cawg/testfiles`**. That branch is upstream `main` (`4973da77`) with these
branches merged in. Each fix is a pull request against contentauth/c2pa-rs from
[mrappard/c2pa-rs-text-support](https://github.com/mrappard/c2pa-rs-text-support); the last
five come from this project. `cawg/testfiles` itself is only local, so until the fixes are
released, rebuilding these files needs the branches merged the same way.

| Branch | PR | What it fixes | Files that need it |
|---|---|---|---|
| `fix/cawg-identity-trusted` | [#3056](https://github.com/contentauth/c2pa-rs/pull/3056) (stacked on #2837) | §7.2 `cawg.identity.trusted` was never issued (TODO CAI-7980), and ICA credentials got neither `trusted` nor `well-formed`. | every trusted and well-formed file |
| `fix/cawg-ica-did-jwk-unpadded` | [#3052](https://github.com/contentauth/c2pa-rs/pull/3052) | `did:jwk` identifiers are unpadded base64url, but were decoded as padded, so most Ed25519 `did:jwk` issuers failed with `cawg.ica.invalid_did_document`. | every ICA file |
| `fix/cawg-ica-signer-payload-length` | [#3053](https://github.com/contentauth/c2pa-rs/pull/3053) | The ICA cross-check zipped the two `referenced_assertions` lists. A credential covering fewer assertions than `signer_payload` passed, and the extra assertions counted as attested. | x14 |
| `fix/cawg-identity-role-cddl` | [#3054](https://github.com/contentauth/c2pa-rs/pull/3054) | `role: []` (and blank roles) were accepted. | x11 |
| `fix/metadata-unparseable-jsonld` | [#3055](https://github.com/contentauth/c2pa-rs/pull/3055) | Any `*.metadata` assertion that the `c2pa.metadata` model couldn't parse made the whole manifest store unreadable. That covered a JSON-LD `@context` array or a missing `@context`. CBOR-stored metadata was also reported as JSON. | m03, mx01, mx03 |
| `fix/cawg-identity-cbor-invalid` | [#2842](https://github.com/contentauth/c2pa-rs/pull/2842) | A malformed identity assertion failed the manifest instead of reporting `cawg.identity.cbor.invalid`. | x10, x11 |
| `fix/cawg-identity-ingredient-references` | [#2843](https://github.com/contentauth/c2pa-rs/pull/2843) | References into an ingredient's claim (§5.1.1) were reported as mismatches. | t04 |
| `fix/cawg-identity-instance-label` | [#2836](https://github.com/contentauth/c2pa-rs/pull/2836) | `cawg.identity__1` was reported under `cawg.identity`. | t03, t06 |
| `fix/cawg-identity-well-formed-on-failure` | [#2837](https://github.com/contentauth/c2pa-rs/pull/2837) | `well-formed` was reported alongside a validation failure. | invalid X.509 cases |
| `fix/cawg-ica-verified-identities`, `fix/cawg-ica-verified-identity-types` | [#2839](https://github.com/contentauth/c2pa-rs/pull/2839), [#2844](https://github.com/contentauth/c2pa-rs/pull/2844) | `verifiedIdentities` problems weren't reported with their §8.1.5 codes. | x18 to x20 |
| `fix/cawg-ica-revocation-unsupported` | [#2840](https://github.com/contentauth/c2pa-rs/pull/2840) | `credentialStatus` wasn't reported. | x21 |
| `fix/cawg-ica-did-unsupported-method` | [#2838](https://github.com/contentauth/c2pa-rs/pull/2838) | Unsupported DID methods were reported as an invalid issuer. | x22 |

The older fix branches came in through `scratch/cawg-all-fixes`. `fix/cawg-x509-status-url` is
already upstream (#2841). Merging onto current `main` needed two test updates, in the merge
commits: upstream now enforces the CAWG interim certificate rules (#3024), so the c2pa-rs test
certificate is an *untrusted* identity, and the ICA regenerator needed the new timestamp API.

### Observed, not fixed

- **Validation state.** c2pa-rs isn't consistent about how CAWG results affect the C2PA
  validation state. An invalid X.509 identity leaves the manifest `Valid`, an invalid ICA one
  makes it `Invalid`. An untrusted X.509 identity lowers `Trusted` to `Valid`, an untrusted ICA
  issuer doesn't. `labels.json` records the state under `sdkValidationState` but doesn't check it.
  CAWG doesn't say how identity results should affect it.
- **No status for some X.509 errors.** An X.509 identity signature with no `x5chain` (or an
  otherwise unparseable COSE structure) produces no `cawg.*` status at all: the error is
  discarded.
- **ICA algorithms.** §8.1 allows ES256/384/512, PS256/384/512 and EdDSA for the credential's COSE
  signature; c2pa-rs accepts only EdDSA. All ICA files here use EdDSA.
- **Sync reading.** The synchronous `Reader` skips ICA validation. The check reads with the async
  API.

## Running it

Needs Rust 1.96 (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)) and the
`../c2pa-rs-cawg-testfiles` worktree described above.

```bash
cargo run --release
```

The run rebuilds `files/`, `labels.json` and `settings/cawg-test-settings.json`, then reads every
file back. It fails if any identity assertion's outcome or expected status code differs from its
label, or if the lint result isn't the expected one. Signatures, instance IDs and timestamps change
each run; the source image and credentials don't.

## License

Licensed under either of the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.

The C2PA test certificates and keys in `settings/` come from
[c2pa-rs](https://github.com/contentauth/c2pa-rs) and stay under its MIT licence; see
[NOTICE](NOTICE). The keys in `credentials/` and `settings/` are published test keys: never
use them for anything but test files.

Unless you explicitly state otherwise, any contribution you submit for inclusion is licensed
as above, without any additional terms or conditions.

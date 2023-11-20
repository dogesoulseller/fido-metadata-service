use std::collections::HashMap;
use serde::{Deserialize, Serialize};

fn bool_true() -> bool { true }

/// FIDO MDS root payload.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MetadataBlobPayload {
	pub legal_header: Option<String>,

	/// Serial number of the MDS data.
	pub no: i64,

	/// Date when the next update will be provided.
	pub next_update: chrono::NaiveDate,

	/// Authenticator entries.
	pub entries: Vec<MetadataBlobPayloadEntry>,
}

/// FIDO MDS Entry. Contains metadata about an authenticator.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-payload-entry-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MetadataBlobPayloadEntry {
	/// Authenticator Attestation ID. FIDO UAF.
	pub aaid: Option<String>,

	/// Authenticator Attestation GUID. FIDO2.
	pub aaguid: Option<String>,

	/// Public key indentifier as a hexadecimal string. Set when aaid and aaguid are not set. Might be set when aaid and aaguid are set. FIDO U2F.
	/// FIDO U2F authenticators usually don't support AAID or AAGUID, and use this field instead.
	pub attestation_certificate_key_identifiers: Option<Vec<String>>,

	/// Metadata statement.
	pub metadata_statement: Option<MetadataStatement>,

	/// Certification status of biometric components.
	pub biometric_status_reports: Option<Vec<BiometricStatusReport>>,

	/// Authenticator status reports.
	pub status_reports: Vec<StatusReport>,

	/// Date since when the status report array was set to the current value.
	pub time_of_last_status_change: chrono::NaiveDate,

	/// URL of a list of untrusted individual authenticators.
	#[serde(rename = "rogueListURL")]
	pub rogue_list_url: Option<String>,

	/// Hash value computed of base64url encoded rogueList at rogue_list_url. Uses JWT header algorithm.
	pub rogue_list_hash: Option<String>,
}

impl MetadataBlobPayloadEntry {
	/// Is this authenticator UAF?
	///
	/// Due to possible errors in the metadata, this function might rarely return false positives or false negatives.
	pub fn is_uaf(&self) -> bool {
		self.metadata_statement.as_ref().map(|meta| meta.protocol_family == "uaf").unwrap_or(false) ||
			(self.aaid.is_some() && self.aaguid.is_some() && self.attestation_certificate_key_identifiers.is_none())
	}

	/// Is this authenticator U2F?
	///
	/// Due to possible errors in the metadata, this function might rarely return false positives or false negatives.
	pub fn is_u2f(&self) -> bool {
		self.metadata_statement.as_ref().map(|meta| meta.protocol_family == "u2f").unwrap_or(false) ||
			(self.aaid.is_none() && self.aaguid.is_none() && self.attestation_certificate_key_identifiers.is_some())
	}

	/// Is this authenticator FIDO2?
	///
	/// Due to possible errors in the metadata, this function might rarely return false positives or false negatives.
	pub fn is_fido2(&self) -> bool {
		self.metadata_statement.as_ref().map(|meta| meta.protocol_family == "fido2").unwrap_or(false) ||
			(self.aaid.is_none() && self.aaguid.is_some() && self.attestation_certificate_key_identifiers.is_none())
	}
}


/// Data about status updates for an authenticator.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#statusreport-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusReport {
	/// Status of the authenticator.
	pub status: AuthenticatorStatus,

	/// Date since when the status code was set. No date means effective immediately.
	pub effective_date: Option<chrono::NaiveDate>,

	/// The authenticatorVersion that this status report applies to.
	pub authenticator_version: Option<u32>,

	/// Base64-encoded DER ITU-X690-2008 PKIX certificate value related to the current status, if applicable.
	pub certificate: Option<String>,

	/// URL where additional information may be found related to the current status, if applicable.
	pub url: Option<String>,

	/// Externally visible aspects of the evaluation.
	pub certification_descriptor: Option<String>,

	/// Unique identifier for the certification.
	pub certificate_number: Option<String>,

	/// Policy version the certification is based on, e.g. "1.0.0".
	pub certification_policy_version: Option<String>,

	/// Security requirements version the certification is based on, e.g. "1.0.0".
	pub certification_requirements_version: Option<String>,
}

/// Status of a biometric component.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BiometricStatusReport {
	/// Achieved level of this component. Specified in <https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html>
	pub cert_level: u16,

	/// Verification metod, e.g. fingerprint_internal. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#user-verification-methods>
	pub modality: String,

	/// Date when certLevel was achieved. No date means effective immediately.
	pub effective_date: Option<String>,

	/// Externally visible aspects of the evaluation.
	pub certification_descriptor: Option<String>,

	/// Unique identifier for the certification.
	pub certificate_number: Option<String>,

	/// Policy version the certification is based on, e.g. "1.0.0".
	pub certification_policy_version: Option<String>,

	/// Security requirements version the certification is based on, e.g. "1.0.0".
	pub certification_requirements_version: Option<String>,
}

/// Metadata statement. Contains metadata about an authenticator.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MetadataStatement {
	pub legal_header: Option<String>,

	/// Authenticator Attestation ID. FIDO UAF.
	pub aaid: Option<String>,

	/// Authenticator Attestation GUID. FIDO2.
	pub aaguid: Option<String>,

	/// Public key indentifier as a hexadecimal string. Set when aaid and aaguid are not set. Might be set when aaid and aaguid are set. FIDO U2F.
	/// FIDO U2F authenticators usually don't support AAID or AAGUID, and use this field instead.
	pub attestation_certificate_key_identifiers: Option<Vec<String>>,

	/// Human-readable desciption of the authenticator. Generally it is the name in English, ASCII max 200 chars.
	pub description: String,

	/// Human-readable alternative descriptions of the authenticator. Translated to other languages. Key-value pairs, key is language code as in RFC5646, value is localized description.
	pub alternative_descriptions: Option<HashMap<String, String>>,

	/// Loweest version meeting requirements of this statement.
	pub authenticator_version: u32,

	/// u2f / uaf / fido2
	pub protocol_family: String,

	/// Schema version.
	pub schema: u16,

	/// FIDO Unified Protocol Versions supported by the authenticator.
	///
	/// - UAF - take OperationHeader field from UAFProtocol
	/// - U2F
	///     + 1.0 = U2F 1.0
	///     + 1.1 = U2F 1.1
	///     + 1.2 = U2F 1.2 CTAP1
	/// - FIDO2
	///     + 2.0 = CTAP 2
	///     + 2.1 = CTAP 2.1
	pub upv: Vec<Version>,

	/// Algorithms supported by the authenticator, e.g. secp256r1_ecdsa_sha256_raw. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms>
	pub authentication_algorithms: Vec<String>,

	/// Pubkey formats supported by the authenticator, e.g. ecc_x962_raw. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats>
	pub public_key_alg_and_encodings: Vec<String>,

	/// Attestation types supported by the authenticator, e.g. basic_full. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types>
	pub attestation_types: Vec<String>,

	/// List of ANDed combinations of verification methods supported by the authenticator.
	pub user_verification_details: VerificationMethodANDCombinations,

	/// Key protection types supported by the authenticator, e.g. secure_element. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#key-protection-types>
	pub key_protection: Vec<String>,

	/// Is uauth key restricted to only sign valid signature assertions.
	#[serde(default = "bool_true")]
	pub is_key_restricted: bool,

	/// Does uauth key usage always require a fresh user verification - doesn't allow caching?
	pub is_fresh_user_verification_required: Option<bool>,

	/// Matcher protection types supported by the authenticator, e.g. software. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#matcher-protection-types>
	pub matcher_protection: Vec<String>,

	/// Claimed cryptographic strength in bits.
	pub crypto_strength: Option<u16>,

	/// Methods by which authenticator communicates with FIDO user device, e.g. nfc. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints>
	pub attachment_hint: Option<Vec<String>>,

	/// Supported transaction confirmation display capabilities, e.g. any, hardware. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types>
	pub tc_display: Vec<String>,

	/// MIME type for confirmation display.
	pub tc_display_content_type: Option<String>,

	/// Alternative descriptors of supported image characteristics for displaying a PNG. Used with image/png.
	#[serde(rename = "tcDisplayPNGCharacteristics")]
	pub tc_display_png_characteristics: Option<Vec<DisplayPNGCharacteristicsDescriptor>>,

	/// Trust anchors for the batch chain in authenticator attestation. PKIX X.509 certificates. Base64-encoded, DER-encoded.
	pub attestation_root_certificates: Vec<String>,

	/// Trust anchors used by ECDAA attestation.
	pub ecdaa_trust_anchors: Option<Vec<EcdaaTrustAnchor>>,

	/// PNG icon as a data URL.
	pub icon: Option<String>,

	/// Extensions supported by UAF authenticators. UAF only.
	pub supported_extensions: Option<Vec<ExtensionDescriptor>>,

	/// Supported versions, extensions, etc. for device as per the authenticator API. FIDO2 only.
	///
	/// This is a JSON object, but it's not known what it contains. It's not documented in the spec as the API is entirely implementation-defined.
	pub authenticator_get_info: Option<serde_json::Value>,
}

pub type VerificationMethodANDCombinations = Vec<Vec<VerificationMethodDescriptor>>;

/// PNG image characteristics.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#displaypngcharacteristicsdescriptor-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DisplayPNGCharacteristicsDescriptor {
	/// Width.
	pub width: u32,

	/// Height.
	pub height: u32,

	/// Bits per sample or palette index.
	pub bit_depth: u8,

	/// PNG image type.
	pub color_type: u8,

	/// Compression method.
	pub compression: u8,

	/// Filter merhod.
	pub filter: u8,

	/// Interlace method.
	pub interlace: u8,

	/// 1 to 256 palette entries.
	pub plte: Option<Vec<RGBPaletteEntry>>,
}

/// RGB palette entry.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dictdef-rgbpaletteentry>
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct RGBPaletteEntry {
	pub r: u16,
	pub g: u16,
	pub b: u16,
}

/// Extension descriptor.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#extensiondescriptor-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ExtensionDescriptor {
	/// Extension identifier.
	pub id: String,

	/// TAG if was assigned. Assigned if they can appear in assertions.
	pub tag: Option<u16>,

	/// Arbitrary data.
	pub data: Option<String>,

	/// If true, unknown extensions must error out if processed by FIDO server, client, asm, or authenticator. If false, ignore.
	pub fail_if_unknown: bool,
}

/// See <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#ecdaatrustanchor-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct EcdaaTrustAnchor {
	pub x: String,
	pub y: String,
	pub c: String,
	pub sx: String,
	pub sy: String,
	#[serde(rename = "G1Curve")]
	pub g_1_curve: String,
}

/// Descriptor of available verification methods.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#verificationmethoddescriptor-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethodDescriptor {
	/// Verification method, e.g. presence_internal. Specified in <https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#user-verification-methods>
	pub user_verification_method: String,

	/// Code accuracy.
	pub ca_desc: Option<CodeAccuracyDescriptor>,

	/// Biometric accuracy.
	pub ba_desc: Option<BiometricAccuracyDescriptor>,

	/// Pattern accuracy.
	pub pa_desc: Option<PatternAccuracyDescriptor>,
}

/// Accuracy and complexity aspects of passcode verification method. For example PIN.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#dictdef-codeaccuracydescriptor>
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct CodeAccuracyDescriptor {
	/// Code radix.
	pub base: u16,

	/// Minimum digits required for code.
	pub min_length: u16,

	/// Retries allowed before authentication blocked.
	pub max_retries: Option<u16>,

	/// Number of seconds to wait after blocking. 0 means it will be permanent or until alternative method succeeds.
	pub block_slowdown: Option<u16>,
}

/// Accuracy and complexity aspects of biometric verification method. For example, fingerprint reader.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct BiometricAccuracyDescriptor {
	/// False rejection rate for template. Percentage of incorrectly denied authentications.
	#[serde(rename = "selfAttestedFRR")]
	pub self_attested_frr: Option<f64>,

	/// False acceptance rate for template. Percentage of incorrectly accepted authentications.
	#[serde(rename = "selfAttestedFAR")]
	pub self_attested_far: Option<f64>,

	/// Maximum number of alternative templates from different body parts used for verification.
	pub max_templates: Option<u16>,

	/// Retries allowed before authentication blocked.
	pub max_retries: Option<u16>,

	/// Number of seconds to wait after blocking. 0 means it will be permanent or until alternative method succeeds.
	pub block_slowdown: Option<u16>,
}

/// Accuracy and complexity aspects of pattern verification method. For example, Android pattern lock.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#patternaccuracydescriptor-dictionary>
#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct PatternAccuracyDescriptor {
	/// Number of possible patterns of minimum length, of which one would be the right one.
	pub min_complexity: u64,

	/// Retries allowed before authentication blocked.
	pub max_retries: Option<u16>,

	/// Number of seconds to wait after blocking. 0 means it will be permanent or until alternative method succeeds.
	pub block_slowdown: Option<u16>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub struct Version {
	pub major: Option<u16>,
	pub minor: Option<u16>,
}

/// Status entry status code.
///
/// See: <https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#authenticatorstatus-enum>
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthenticatorStatus {
	/// Not FIDO Certified.
	///
	/// Contains:
	/// - effectiveDate - When status was set
	/// - authenticatorVersion - Minimum version of authenticator
	/// - url - URL with more information
	NotFidoCertified,

	/// Deprecated. Passed FIDO certification. See <https://fidoalliance.org/certification/authenticator-certification-levels/>
	///
	/// Contains:
	/// - effectiveDate - When certification was issued
	/// - authenticatorVersion - Minimum version of authenticator
	/// - certificationDescriptor - Authenticator description
	/// - certificateNumber
	/// - certificationPolicyVersion
	/// - certificationRequirementsVersion
	/// - url - URL to certificate or news article
	FidoCertified,

	/// Level 1 FIDO Certified. Same fields as FidoCertified. See <https://fidoalliance.org/certification/authenticator-certification-levels/authenticator-level-1/>
	FidoCertifiedL1,

	/// Level 1+ FIDO Certified. Same fields as FidoCertified. See <https://fidoalliance.org/authenticator-level-1//>
	FidoCertifiedL1Plus,

	/// Level 2 FIDO Certified. Same fields as FidoCertified. See <https://fidoalliance.org/certification/authenticator-certification-levels/authenticator-level-2/>
	FidoCertifiedL2,

	/// Level 2+ FIDO Certified. Same fields as FidoCertified. Seems to be undocumented.
	FidoCertifiedL2Plus,

	/// Level 3 FIDO Certified. Same fields as FidoCertified. See <https://fidoalliance.org/certification/authenticator-certification-levels/authenticator-level-3/>
	FidoCertifiedL3,

	/// Level 3+ FIDO Certified. Same fields as FidoCertified. See <https://fidoalliance.org/certification/authenticator-certification-levels/authenticator-level-3-plus/>
	FidoCertifiedL3Plus,

	/// This authenticator should not be trusted for any reason - fraud, deliberate backdoor.
	///
	/// Contains:
	/// - effectiveDate - When incident was reported
	/// - authenticatorVersion - Minimum version of authenticator
	/// - url - URL to article explaining the incident
	Revoked,

	/// Malware is able to bypass user verification. Means it can be used without user consent or knowledge.
	///
	/// Contains:
	/// - effectiveDate - When incident was reported
	/// - authenticatorVersion - Minimum version of authenticator
	/// - url - URL to article explaining the incident
	UserVerificationBypass,

	/// Attestation key for this authenticator is known to be compromised. Should check certificate field.
	///
	/// Contains:
	/// - effectiveDate - When incident was reported
	/// - authenticatorVersion - Minimum version of authenticator
	/// - certificate - Compromised attestation root. If missing, all authenticators are compromised
	/// - url - URL to article explaining the incident
	AttestationKeyCompromise,

	/// Contains weaknesses that allow keys to be compromised remotely and should not be trusted.
	///
	/// Contains:
	/// - effectiveDate - When incident was reported
	/// - authenticatorVersion - Minimum version of authenticator
	/// - url - URL to article explaining the incident
	UserKeyRemoteCompromise,

	/// Contains weaknesses that allow keys to be compromised in physical possession and should not be trusted.
	///
	/// Contains:
	/// - effectiveDate - When incident was reported
	/// - authenticatorVersion - Minimum version of authenticator
	/// - url - URL to article explaining the incident
	UserKeyPhysicalCompromise,

	/// Firmware update is available.
	///
	/// Contains:
	/// - effectiveDate - When incident was reported
	/// - authenticatorVersion - New version that is available
	/// - url - URL to page with update info
	UpdateAvailable,

	/// Vendor has submitted the self-certification checklist.
	///
	/// Contains:
	/// -  effectiveDate - When incident was reported
	/// -  authenticatorVersion - New authenticator version
	/// -  url - URL to page with checklist, if provided
	SelfAssertionSubmitted,
}

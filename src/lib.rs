//! # FIDO Metadata Service (MDS) Client
//! This crate provides a client for the FIDO Metadata Service (MDS) as defined in the [FIDO Metadata Service Specification](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html).
//!
//! No verification of the signature is currently performed. This is planned for a future version.
//!
//! ## Usage
//! The crate provides two functions for fetching and parsing the FIDO MDS BLOB, as well as one function for parsing an already downloaded or cached BLOB.
//!
//! The BLOB should be cached and updated rarely. The payload contains a `next_update` field, which specifies when the BLOB should be updated at the latest.
//!
//! ### Fetching and parsing the FIDO MDS BLOB
//! - [fetch_fido_mds()] function fetches the FIDO MDS BLOB from the FIDO MDS server and parses it. This function is asynchronous and requires the `download` feature.
//! - [fetch_fido_mds_blocking()] function does the same, but is blocking. This function requires the `download` and `blocking` features.
//!
//! ### Parsing an already downloaded or cached FIDO MDS BLOB
//! - [parse_fido_mds()] parses an already downloaded or cached FIDO MDS BLOB. This function does not require any features.
//!
//! ## Features
//! - `default` - Enables `download` and `rustls-tls` features.
//! - `download` - Enables fetching from MDS server.
//! - `blocking` - Enables fetching from MDS server using blocking function. Enables `download` feature.
//! - `rustls-tls` - Enables TLS support using rustls. This is the default TLS backend. Enables `download` feature.
//! - `native-tls` - Enables TLS support using native-tls. Enables `download` feature.
//!
//! ## TODO
//!
//! - [ ] Verifying the signature.
//! - [ ] Caching the BLOB.
//! - [ ] Diff between two BLOBs.

pub mod blob_payload;
pub mod error;

use base64::Engine;
use error::FidoMdsError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use crate::blob_payload::MetadataBlobPayload;


/// FIDO MDS JWT Header contents.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct FidoMdsJwtHeader {
	pub alg: String,
	pub typ: String,
	pub x5c: Vec<String>,
}

/// FIDO MDS BLOB content. This is the result of parsing a FIDO MDS BLOB.
#[derive(Debug, Clone)]
pub struct FidoMds {
	/// Prefix - header.
	pub jwt_header: FidoMdsJwtHeader,

	/// Middle - authenticator information.
	pub payload: MetadataBlobPayload,

	/// Suffix - signature.
	pub signature: Vec<u8>,
}

#[cfg(feature = "download")]
const FIDO_MDS_URL: &str = "https://mds3.fidoalliance.org";

#[cfg(all(feature = "download", feature = "blocking"))]
/// Fetches the FIDO MDS BLOB from the FIDO MDS server and parses it. This is a blocking function.
///
/// Requires the `download` and `blocking` features.
pub fn fetch_fido_mds_blocking() -> Result<FidoMds, FidoMdsError> {
	let data = reqwest::blocking::get(FIDO_MDS_URL)?.text()?;

	parse_fido_mds(&data)
}

#[cfg(feature = "download")]
/// Fetches the FIDO MDS BLOB from the FIDO MDS server and parses it.
pub async fn fetch_fido_mds() -> Result<FidoMds, FidoMdsError> {
	let data = reqwest::get(FIDO_MDS_URL).await?.text().await?;

	parse_fido_mds(&data)
}

/// Parses a FIDO MDS BLOB.
///
/// Expects data to be in the exact format as returned by the FIDO MDS server - base64url encoded with no padding, with the header, payload, and signature separated by periods.
///
/// # Arguments
/// * `data` - The FIDO MDS BLOB to parse.
pub fn parse_fido_mds(data: &str) -> Result<FidoMds, FidoMdsError> {
	// Data in the MDS in split into 3 parts, separated by a period.
	// The first part is the header, the second part is the payload, and the third part is the signature.
	let mut split_result = data.splitn(3, '.');

	// All fields are required, so if any of them are missing, return an error.
	let jwt_header_b64 = split_result.next().ok_or(FidoMdsError::JwtMissing)?;
	let tbs_payload_b64 = split_result.next().ok_or(FidoMdsError::PayloadMissing)?;
	let signature_b64 = split_result.next().ok_or(FidoMdsError::SignatureMissing)?;

	// Decode the base64 data for each part. The header and payload are UTF-8 JSON. Signature is just raw bytes.
	let jwt_header_str = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(jwt_header_b64)?)?;
	let tbs_payload_str = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(tbs_payload_b64)?)?;
	let signature: Vec<u8> = BASE64_URL_SAFE_NO_PAD.decode(signature_b64)?;

	// Parse the JSON data.
	let jwt_header: FidoMdsJwtHeader = serde_json::from_str(&jwt_header_str)?;
	let payload: MetadataBlobPayload = serde_json::from_str(&tbs_payload_str)?;

	Ok(
		FidoMds {
			jwt_header,
			payload,
			signature,
		}
	)
}

#[cfg(test)]
mod tests {
	use crate::blob_payload::AuthenticatorStatus::{FidoCertified, FidoCertifiedL1, FidoCertifiedL2};
	use super::*;

	const TEST_MDS: &str = include_str!("../testdata/blob.jwt");

	#[test]
	fn mds_parses() {
		let result = parse_fido_mds(TEST_MDS).expect("Failed to parse MDS");

		assert_eq!(result.signature.len(), 256);

		assert_eq!(result.jwt_header.alg, "RS256");
		assert_eq!(result.jwt_header.typ, "JWT");
		assert_eq!(result.jwt_header.x5c.len(), 2);

		assert_ne!(result.payload.entries.len(), 0);
	}

	#[test]
	fn mds_payload_parses() {
		// We use an example from the spec here.
		// Checks most of the fields (the important ones) to make sure they're there and parsed correctly.
		let payload = parse_fido_mds(TEST_MDS).expect("Failed to parse MDS").payload;

		assert_eq!(&payload.next_update.format("%Y-%m-%d").to_string(), "2023-12-01");

		// Working on known good data.
		let working_entry = payload.entries.iter()
			.find(|entry| entry.aaguid.clone().unwrap_or_default() == "0bb43545-fd2c-4185-87dd-feb0b2916ace")
			.expect("Failed to find working entry").clone();

		assert_eq!(working_entry.aaguid.unwrap(), "0bb43545-fd2c-4185-87dd-feb0b2916ace");

		let status_report = working_entry.status_reports.first().unwrap();
		assert_eq!(working_entry.status_reports.len(), 3);
		assert_eq!(status_report.status, FidoCertifiedL2);
		assert_eq!(status_report.effective_date.unwrap().format("%Y-%m-%d").to_string(), "2023-03-28");
		assert_eq!(status_report.url.as_ref().unwrap(), "https://www.yubico.com/products/");
		assert_eq!(status_report.certification_descriptor.as_ref().unwrap(), "Security Key NFC by Yubico - Enterprise Edition");
		assert_eq!(status_report.certificate_number.as_ref().unwrap(), "FIDO20020230328003");
		assert_eq!(status_report.certification_policy_version.as_ref().unwrap(), "1.3");
		assert_eq!(status_report.certification_requirements_version.as_ref().unwrap(), "1.3");

		let metadata_statement = working_entry.metadata_statement.unwrap();
		assert_eq!(metadata_statement.aaguid.unwrap(), "0bb43545-fd2c-4185-87dd-feb0b2916ace");
		assert_eq!(metadata_statement.description, "Security Key NFC by Yubico - Enterprise Edition");
		assert_eq!(metadata_statement.protocol_family, "fido2");
		assert_eq!(metadata_statement.upv.first().unwrap().major.unwrap(), 1);
		assert_eq!(metadata_statement.upv.first().unwrap().minor.unwrap(), 0);
		assert_eq!(metadata_statement.authentication_algorithms.first().unwrap(), "ed25519_eddsa_sha512_raw");
		assert_eq!(metadata_statement.authentication_algorithms.get(1).unwrap(), "secp256r1_ecdsa_sha256_raw");
		assert_eq!(metadata_statement.public_key_alg_and_encodings.first().unwrap(), "cose");
		assert_eq!(metadata_statement.attestation_types.first().unwrap(), "basic_full");

		let first_user_verification_details = metadata_statement.user_verification_details.first().unwrap().first().unwrap();
		assert_eq!(metadata_statement.user_verification_details.len(), 4);
		assert_eq!(first_user_verification_details.user_verification_method, "passcode_external");
		assert_eq!(first_user_verification_details.ca_desc.unwrap().base, 64);
		assert_eq!(first_user_verification_details.ca_desc.unwrap().min_length, 4);
		assert_eq!(first_user_verification_details.ca_desc.unwrap().max_retries.unwrap(), 8);
		assert_eq!(first_user_verification_details.ca_desc.unwrap().block_slowdown.unwrap(), 0);
		assert!(first_user_verification_details.ba_desc.is_none());
		assert!(first_user_verification_details.pa_desc.is_none());

		assert_eq!(metadata_statement.key_protection, vec!["hardware", "secure_element"]);
		assert_eq!(metadata_statement.matcher_protection.first().unwrap(), "on_chip");
		assert_eq!(metadata_statement.crypto_strength.unwrap(), 128);
		assert_eq!(metadata_statement.attachment_hint.unwrap(), vec!["external", "wired", "wireless", "nfc"]);

		let authenticator_get_info = metadata_statement.authenticator_get_info.as_ref().unwrap();
		assert_eq!(authenticator_get_info.get("versions").unwrap().as_array().unwrap().len(), 3);
		assert_eq!(authenticator_get_info.get("extensions").unwrap().as_array().unwrap().len(), 2);
		assert_eq!(authenticator_get_info.get("maxMsgSize").unwrap().as_u64().unwrap(), 1200);
		assert_eq!(authenticator_get_info.get("aaguid").unwrap().as_str().unwrap(), "0bb43545fd2c418587ddfeb0b2916ace");

		// Checks the other two status reports just to make sure they're there.
		assert_eq!(working_entry.status_reports.get(1).unwrap().status, FidoCertifiedL1);
		assert_eq!(working_entry.status_reports.get(2).unwrap().status, FidoCertified);
	}
}

pub mod blob_payload;
pub mod error;

use base64::Engine;
use error::FidoMdsError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use crate::blob_payload::MetadataBlobPayload;

/// FIDO MDS JWT Header contents.
#[derive(Debug, Clone, Deserialize, Serialize)]
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

/// Fetches the FIDO MDS BLOB from the FIDO MDS server and parses it. This is a blocking function.
pub fn fetch_fido_mds() -> Result<FidoMds, FidoMdsError> {
    // TODO: Error checks
    let data = reqwest::blocking::get("https://mds3.fidoalliance.org").unwrap().text().unwrap();

    parse_fido_mds_jwt(&data)
}

/// Parses a FIDO MDS BLOB.
///
/// Expects data to be in the exact format as returned by the FIDO MDS server - base64 encoded, with the header, payload, and signature separated by periods.
///
/// # Arguments
///
/// * `data` - The FIDO MDS BLOB to parse.
pub fn parse_fido_mds_jwt(data: &str) -> Result<FidoMds, FidoMdsError> {
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
            signature
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MDS: &str = include_str!("../testdata/blob.jwt");

    #[test]
    fn mds_parses() {
        let result = parse_fido_mds_jwt(TEST_MDS).expect("Failed to parse MDS");

		assert_eq!(result.jwt_header.alg, "RS256");
		assert_eq!(result.jwt_header.typ, "JWT");
		assert_eq!(result.jwt_header.x5c.len(), 2);
    }


}

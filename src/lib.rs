pub mod blob_payload;
pub mod error;

use base64::Engine;
use error::FidoMdsError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use crate::blob_payload::MetadataBlobPayload;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FidoMdsJwtHeader {
    pub alg: String,
    pub typ: String,
    pub x5c: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct FidoMds {
    pub jwt_header: FidoMdsJwtHeader,
    pub payload: MetadataBlobPayload,
    pub signature: Vec<u8>,
}

// TODO: JWT validation

pub fn fetch_fido_mds() -> String {
    // TODO: Error checks
    reqwest::blocking::get("https://mds3.fidoalliance.org").unwrap().text().unwrap()
}

pub fn parse_fido_mds_jwt(jwt: &str) -> Result<FidoMds, FidoMdsError> {
    let mut split_result = jwt.splitn(3, '.');

    let jwt_header_b64 = split_result.next().ok_or(FidoMdsError::JwtMissing)?;
    let tbs_payload_b64 = split_result.next().ok_or(FidoMdsError::PayloadMissing)?;
    let signature_b64 = split_result.next().ok_or(FidoMdsError::SignatureMissing)?;

	let jwt_header_str = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(jwt_header_b64)?)?;
	let tbs_payload_str = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(tbs_payload_b64)?)?;

    let jwt_header: FidoMdsJwtHeader = serde_json::from_str(&jwt_header_str)?;
    let payload: MetadataBlobPayload = serde_json::from_str(&tbs_payload_str)?;
    let signature: Vec<u8> = BASE64_URL_SAFE_NO_PAD.decode(signature_b64)?;

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

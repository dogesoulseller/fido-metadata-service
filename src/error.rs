#[derive(Debug)]
pub enum FidoMdsError {
	/// Required JWT header is missing.
    JwtMissing,

	/// Payload is missing.
    PayloadMissing,

	/// Signature is missing.
    SignatureMissing,

	/// IO error.
    IoError(std::io::Error),

	/// Base64 decoding error.
    Base64Error(base64::DecodeError),

	/// JSON deserialization error.
    JsonError(serde_json::Error),

	/// Error converting part to UTF-8.
	UTF8Error(std::string::FromUtf8Error)
}

impl From<std::io::Error> for FidoMdsError {
	fn from(err: std::io::Error) -> Self {
		FidoMdsError::IoError(err)
	}
}

impl From<base64::DecodeError> for FidoMdsError {
	fn from(err: base64::DecodeError) -> Self {
		FidoMdsError::Base64Error(err)
	}
}

impl From<serde_json::Error> for FidoMdsError {
	fn from(err: serde_json::Error) -> Self {
		FidoMdsError::JsonError(err)
	}
}

impl From<std::string::FromUtf8Error> for FidoMdsError {
	fn from(err: std::string::FromUtf8Error) -> Self {
		FidoMdsError::UTF8Error(err)
	}
}
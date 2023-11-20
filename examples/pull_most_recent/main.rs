extern crate fido_metadata_service;

fn main() {
	eprintln!("Fetching most recent FIDO MDS BLOB...");
	let mds = match fido_metadata_service::fetch_fido_mds_blocking() {
		Ok(res) => res,
		Err(e) => panic!("Error fetching FIDO MDS BLOB: {:?}", e),
	};

	eprintln!("FIDO MDS BLOB fetched. Header: {:?}", mds.jwt_header);
}

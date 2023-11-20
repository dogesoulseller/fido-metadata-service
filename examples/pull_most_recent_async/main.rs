fn main() {
	tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
		eprintln!("Fetching most recent FIDO MDS BLOB asynchronously...");
		let mds = match fido_metadata_service::fetch_fido_mds().await {
			Ok(res) => res,
			Err(e) => panic!("Error fetching FIDO MDS BLOB asynchronously: {:?}", e),
		};

		eprintln!("FIDO MDS BLOB fetched asynchronously. Header: {:?}", mds.jwt_header);
	});
}

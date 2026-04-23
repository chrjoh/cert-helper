fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if std::env::var_os("CARGO_FEATURE_PQC").is_some() {
        let version = std::env::var("DEP_OPENSSL_VERSION_NUMBER")
            .expect("DEP_OPENSSL_VERSION_NUMBER not set; openssl-sys must be a direct dependency");
        let n = u64::from_str_radix(&version, 16)
            .unwrap_or_else(|e| panic!("DEP_OPENSSL_VERSION_NUMBER not valid hex: {}", e));
        if n < 0x3050000f {
            panic!(
                "The `pqc` feature requires OpenSSL >= 3.5.0 (ML-DSA / SLH-DSA). \
                 Linked OpenSSL version is 0x{:08x}. Rebuild against OpenSSL 3.5+ \
                 or disable the `pqc` feature.",
                n
            );
        }
    }
}

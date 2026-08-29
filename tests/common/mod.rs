use std::{process::Command, sync::OnceLock};

/// Generate a GitHub App-compatible RSA signing key once per test process.
/// Keeping this runtime-generated avoids committing a reusable private key.
pub fn github_app_signing_key() -> &'static [u8] {
    static KEY: OnceLock<Vec<u8>> = OnceLock::new();
    KEY.get_or_init(|| {
        let output = Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
            ])
            .output()
            .expect("openssl must be installed for GitHub provider tests");
        assert!(
            output.status.success(),
            "openssl failed to generate an RSA key"
        );
        output.stdout
    })
}

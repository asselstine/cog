use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct SecretBox(Aes256Gcm);

impl SecretBox {
    pub fn new(master: &[u8]) -> Self {
        let key: [u8; 32] = Sha256::digest(master).into();
        Self(Aes256Gcm::new(&key.into()))
    }
    pub fn seal(&self, plaintext: &[u8]) -> anyhow::Result<String> {
        let nonce: [u8; 12] = rand::random();
        let ciphertext = self
            .0
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow::anyhow!("secret encryption failed"))?;
        let mut out = nonce.to_vec();
        out.extend(ciphertext);
        Ok(URL_SAFE_NO_PAD.encode(out))
    }
    pub fn open(&self, encoded: &str) -> anyhow::Result<Vec<u8>> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        anyhow::ensure!(bytes.len() >= 28, "invalid encrypted secret");
        self.0
            .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
            .map_err(|_| anyhow::anyhow!("secret authentication failed"))
    }
}

pub fn random_token(bytes: usize) -> String {
    let mut value = vec![0; bytes];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

pub fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

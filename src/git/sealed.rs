use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

const INFO: &[u8] = b"cog-git-sealed-credential-v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedCredentialRequest {
    pub repository_id: String,
    pub recipient_public_key: String,
    pub request_nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedCredentialEnvelope {
    pub version: u8,
    pub repository_id: String,
    pub origin: String,
    pub request_nonce: String,
    pub sender_public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialPayload {
    pub username: String,
    pub password: String,
    pub repository_id: String,
    pub origin: String,
    pub expires_at: i64,
}

pub fn new_recipient() -> (StaticSecret, String) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, URL_SAFE_NO_PAD.encode(public.as_bytes()))
}

pub fn seal(
    request: &SealedCredentialRequest,
    origin: &str,
    payload: &CredentialPayload,
) -> anyhow::Result<SealedCredentialEnvelope> {
    let recipient = decode_array::<32>(&request.recipient_public_key, "recipient public key")?;
    let recipient = PublicKey::from(recipient);
    let sender_secret = StaticSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_secret);
    let shared = sender_secret.diffie_hellman(&recipient);
    anyhow::ensure!(shared.was_contributory(), "invalid recipient public key");
    let nonce: [u8; 12] = rand::random();
    let key = derive_key(shared.as_bytes(), request.request_nonce.as_bytes())?;
    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .expect("AES-256 key length")
        .encrypt((&nonce).into(), serde_json::to_vec(payload)?.as_ref())
        .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
    Ok(SealedCredentialEnvelope {
        version: 1,
        repository_id: request.repository_id.clone(),
        origin: origin.to_owned(),
        request_nonce: request.request_nonce.clone(),
        sender_public_key: URL_SAFE_NO_PAD.encode(sender_public.as_bytes()),
        nonce: URL_SAFE_NO_PAD.encode(nonce),
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn open(
    envelope: &SealedCredentialEnvelope,
    recipient_secret: &StaticSecret,
) -> anyhow::Result<CredentialPayload> {
    anyhow::ensure!(
        envelope.version == 1,
        "unsupported sealed credential version"
    );
    let sender = PublicKey::from(decode_array::<32>(
        &envelope.sender_public_key,
        "sender public key",
    )?);
    let shared = recipient_secret.diffie_hellman(&sender);
    anyhow::ensure!(shared.was_contributory(), "invalid sender public key");
    let nonce = decode_array::<12>(&envelope.nonce, "encryption nonce")?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&envelope.ciphertext)
        .map_err(|_| anyhow::anyhow!("invalid ciphertext"))?;
    let key = derive_key(shared.as_bytes(), envelope.request_nonce.as_bytes())?;
    let plaintext = Aes256Gcm::new_from_slice(&key)
        .expect("AES-256 key length")
        .decrypt((&nonce).into(), ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("sealed credential authentication failed"))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

fn derive_key(shared: &[u8; 32], request_nonce: &[u8]) -> anyhow::Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(request_nonce), shared)
        .expand(INFO, &mut key)
        .map_err(|_| anyhow::anyhow!("credential key derivation failed"))?;
    Ok(key)
}

pub fn decode_array<const N: usize>(value: &str, label: &str) -> anyhow::Result<[u8; N]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| anyhow::anyhow!("invalid {label}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {label} length"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_credential_round_trip_and_tamper_rejection() {
        let (secret, public) = new_recipient();
        let request = SealedCredentialRequest {
            repository_id: uuid::Uuid::new_v4().to_string(),
            recipient_public_key: public,
            request_nonce: crate::crypto::random_token(32),
        };
        let payload = CredentialPayload {
            username: "cog".into(),
            password: "secret".into(),
            repository_id: request.repository_id.clone(),
            origin: "https://cog.example".into(),
            expires_at: 123,
        };
        let mut envelope = seal(&request, &payload.origin, &payload).unwrap();
        assert_eq!(open(&envelope, &secret).unwrap().password, "secret");
        envelope.ciphertext.push('A');
        assert!(open(&envelope, &secret).is_err());
    }
}

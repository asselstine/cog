use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use cog::crypto::*;
#[test]
fn round_trip_and_tamper() {
    let b = SecretBox::new(b"a sufficiently long test master key");
    let sealed = b.seal(b"secret").unwrap();
    assert_eq!(b.open(&sealed).unwrap(), b"secret");
    let mut raw = URL_SAFE_NO_PAD.decode(sealed).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    assert!(b.open(&URL_SAFE_NO_PAD.encode(raw)).is_err());
    assert!(b.open(&URL_SAFE_NO_PAD.encode([0_u8; 27])).is_err());
    assert!(b.open("bad").is_err());
    assert_ne!(random_token(32), random_token(32));
    assert_eq!(token_hash("x"), token_hash("x"));
}

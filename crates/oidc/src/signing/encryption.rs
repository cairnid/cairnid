use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::OidcError;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyEncryptionKey {
    bytes: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl std::fmt::Debug for KeyEncryptionKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KeyEncryptionKey([redacted])")
    }
}

impl KeyEncryptionKey {
    pub fn from_base64_url_no_pad(value: &str) -> Result<Self, OidcError> {
        let decoded = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(value.trim())
                .map_err(|_| OidcError::InvalidKeyEncryptionKey)?,
        );
        if decoded.len() != 32 {
            return Err(OidcError::InvalidKeyEncryptionKey);
        }

        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(decoded.as_slice());
        Ok(Self { bytes })
    }

    pub(super) fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(&self.bytes).expect("AES-256-GCM key length is fixed")
    }
}

pub fn generate_key_encryption_key() -> String {
    let key = Aes256Gcm::generate_key(&mut AeadOsRng);
    URL_SAFE_NO_PAD.encode(key)
}

pub fn encrypt_secret(
    secret: &str,
    key_encryption_key: &KeyEncryptionKey,
    aad: &str,
) -> Result<EncryptedSecret, OidcError> {
    let cipher = key_encryption_key.cipher();
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: secret.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| OidcError::SecretEncryption)?;

    Ok(EncryptedSecret {
        ciphertext,
        nonce: nonce.to_vec(),
    })
}

pub fn decrypt_secret(
    encrypted: &EncryptedSecret,
    key_encryption_key: &KeyEncryptionKey,
    aad: &str,
) -> Result<String, OidcError> {
    let cipher = key_encryption_key.cipher();
    let nonce_bytes: [u8; 12] = encrypted
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| OidcError::SecretDecryption)?;
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: encrypted.ciphertext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| OidcError::SecretDecryption)?,
    );

    std::str::from_utf8(plaintext.as_slice())
        .map(str::to_owned)
        .map_err(|_| OidcError::SecretDecryption)
}

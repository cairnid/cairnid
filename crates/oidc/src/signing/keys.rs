use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadCore, OsRng as AeadOsRng, Payload},
};
use cairn_domain::SigningKeyMaterial;
use openssl::{pkey::PKey, rsa::Rsa};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{KeyEncryptionKey, SigningMaterial, rsa_public_jwk};
use crate::OidcError;

pub fn generate_encrypted_signing_key(
    key_encryption_key: &KeyEncryptionKey,
) -> Result<SigningKeyMaterial, OidcError> {
    let private_key = Rsa::generate(3072).map_err(|_| OidcError::SigningKeyGeneration)?;
    let key_pair = PKey::from_rsa(private_key).map_err(|_| OidcError::SigningKeyGeneration)?;
    let private_key_pem_bytes = Zeroizing::new(
        key_pair
            .private_key_to_pem_pkcs8()
            .map_err(|_| OidcError::SigningKeyGeneration)?,
    );
    let private_key_pem = std::str::from_utf8(private_key_pem_bytes.as_slice())
        .map(str::to_owned)
        .map_err(|_| OidcError::SigningKeyGeneration)?;
    let key_id = format!("rs256-{}", Uuid::new_v4());
    let signing = SigningMaterial {
        key_id: key_id.clone(),
        public_jwk: rsa_public_jwk(&key_id, &private_key_pem)?,
        private_key_pem,
    };

    encrypt_signing_material(&signing, key_encryption_key)
}

pub fn encrypt_signing_material(
    signing: &SigningMaterial,
    key_encryption_key: &KeyEncryptionKey,
) -> Result<SigningKeyMaterial, OidcError> {
    let cipher = key_encryption_key.cipher();
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let aad = signing_key_aad(&signing.key_id);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: signing.private_key_pem.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| OidcError::SigningKeyEncryption)?;

    Ok(SigningKeyMaterial {
        kid: signing.key_id.clone(),
        algorithm: "RS256".to_owned(),
        public_jwk: signing.public_jwk.clone(),
        private_key_ciphertext: ciphertext,
        private_key_nonce: nonce.to_vec(),
        signing_active: true,
        created_at: OffsetDateTime::now_utc(),
        retired_at: None,
    })
}

pub fn decrypt_signing_material(
    stored: &SigningKeyMaterial,
    key_encryption_key: &KeyEncryptionKey,
) -> Result<SigningMaterial, OidcError> {
    if stored.algorithm != "RS256" || stored.retired_at.is_some() {
        return Err(OidcError::InvalidSigningKey);
    }

    let private_key_pem = decrypt_signing_private_key_pem(stored, key_encryption_key)?;
    Ok(SigningMaterial {
        key_id: stored.kid.clone(),
        private_key_pem: private_key_pem.to_string(),
        public_jwk: stored.public_jwk.clone(),
    })
}

pub fn reencrypt_signing_key_material(
    stored: &SigningKeyMaterial,
    old_key_encryption_key: &KeyEncryptionKey,
    new_key_encryption_key: &KeyEncryptionKey,
) -> Result<SigningKeyMaterial, OidcError> {
    if stored.algorithm != "RS256" {
        return Err(OidcError::InvalidSigningKey);
    }

    let private_key_pem = decrypt_signing_private_key_pem(stored, old_key_encryption_key)?;
    let cipher = new_key_encryption_key.cipher();
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let aad = signing_key_aad(&stored.kid);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: private_key_pem.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| OidcError::SigningKeyEncryption)?;

    Ok(SigningKeyMaterial {
        kid: stored.kid.clone(),
        algorithm: stored.algorithm.clone(),
        public_jwk: stored.public_jwk.clone(),
        private_key_ciphertext: ciphertext,
        private_key_nonce: nonce.to_vec(),
        signing_active: stored.signing_active,
        created_at: stored.created_at,
        retired_at: stored.retired_at,
    })
}

fn decrypt_signing_private_key_pem(
    stored: &SigningKeyMaterial,
    key_encryption_key: &KeyEncryptionKey,
) -> Result<Zeroizing<String>, OidcError> {
    let cipher = key_encryption_key.cipher();
    let nonce_bytes: [u8; 12] = stored
        .private_key_nonce
        .as_slice()
        .try_into()
        .map_err(|_| OidcError::InvalidSigningKey)?;
    let nonce = aes_gcm::Nonce::from(nonce_bytes);
    let aad = signing_key_aad(&stored.kid);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: stored.private_key_ciphertext.as_ref(),
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| OidcError::SigningKeyDecryption)?,
    );
    std::str::from_utf8(plaintext.as_slice())
        .map(str::to_owned)
        .map(Zeroizing::new)
        .map_err(|_| OidcError::InvalidSigningKey)
}

fn signing_key_aad(key_id: &str) -> String {
    format!("cairnid:oidc-signing-key:{key_id}:RS256")
}

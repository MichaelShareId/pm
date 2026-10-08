use anyhow::{bail, Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MASTER_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_KEY_LEN]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; MASTER_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; MASTER_KEY_LEN] {
        &self.0
    }
}

pub fn generate_master_key() -> MasterKey {
    let mut bytes = [0u8; MASTER_KEY_LEN];
    rand::thread_rng().fill_bytes(&mut bytes);
    MasterKey::from_bytes(bytes)
}

pub fn encrypt(key: &MasterKey, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    Ok((nonce_bytes.to_vec(), ciphertext))
}

pub fn decrypt(
    key: &MasterKey,
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        bail!("invalid nonce length");
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decryption failed (wrong key or corrupt data)"))?;
    Ok(Zeroizing::new(plaintext))
}

pub fn master_key_from_hex(hex_str: &str) -> Result<MasterKey> {
    let bytes = hex::decode(hex_str.trim()).context("decode master key hex")?;
    if bytes.len() != MASTER_KEY_LEN {
        bail!("master key must be {MASTER_KEY_LEN} bytes");
    }
    let mut arr = [0u8; MASTER_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(MasterKey::from_bytes(arr))
}

pub fn master_key_to_hex(key: &MasterKey) -> String {
    hex::encode(key.as_bytes())
}

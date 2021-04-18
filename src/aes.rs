use openssl::symm::{ self, Cipher };
use rand::{ thread_rng, RngCore };
use zeroize::Zeroize;

use crate::error::Error;

#[cfg(test)]
#[path = "./aes.test.rs"]
mod aes_test;

pub fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
  let crypter = Crypter::new(key);
  crypter.encrypt(data)
}

pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
  let crypter = Crypter::new(key);
  crypter.decrypt(data)
}

pub fn ecb_128(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_128_ecb(), false)
}
pub fn cbc_128(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_128_cbc(), false)
}
pub fn cbc_192(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_192_cbc(), false)
}
pub fn cbc_256(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_256_cbc(), false)
}
pub fn gcm_128(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_128_gcm(), true)
}
pub fn gcm_192(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_192_gcm(), true)
}
pub fn gcm_256(key: &[u8]) -> Crypter {
  Crypter::from(key, Cipher::aes_256_gcm(), true)
}

pub struct Crypter<'a> {
  aad: Vec<u8>,
  key: Vec<u8>,
  cipher: Cipher,
  config: argon2::Config<'a>,
  iv_len: usize,
  is_aead: bool,
}

impl<'a> Crypter<'a> {
  const TAG_BYTES:  usize = 16;
  const SALT_BYTES: usize = 16;

  pub fn new(key: &[u8]) -> Self {
    Crypter::from(key, Cipher::aes_256_gcm(), true)
  }

  fn from(key: &[u8], cipher: Cipher, is_aead: bool) -> Self {
    let mut config = argon2::Config::default();
    config.hash_length = cipher.key_len() as u32;

    Crypter {
      cipher,
      config,
      is_aead,
      aad: Vec::new(),
      key: Vec::from(key),
      iv_len: cipher.iv_len().unwrap_or(0),
    }
  }

  pub fn set_aad(&mut self, aad: &[u8]) {
    self.aad = aad.to_vec();
  }

  pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut iv = vec![0; self.iv_len];
    thread_rng().fill_bytes(&mut iv);

    let mut salt = [0; Crypter::SALT_BYTES];
    thread_rng().fill_bytes(&mut salt);
    let secret = argon2::hash_raw(&self.key, &salt, &self.config)?;

    let mut tag = [0; Crypter::TAG_BYTES];
    let encrypted = if self.is_aead {
      symm::encrypt_aead(self.cipher, &secret, Some(&iv), &self.aad, data, &mut tag)
    } else {
      symm::encrypt(self.cipher, &secret, Some(&iv), data)
    }?;

    let capacity = salt.len() + self.iv_len + encrypted.len();
    let mut result: Vec<u8> = Vec::with_capacity(capacity);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&tag);
    result.extend_from_slice(&iv);
    result.extend(encrypted);

    Ok(result)
  }

  pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let (salt, data) = data.split_at(Crypter::SALT_BYTES);
    let (tag,  data) = data.split_at(Crypter::TAG_BYTES);
    let secret = argon2::hash_raw(&self.key, &salt, &self.config)?;
    let (iv, data) = match self.iv_len {
      0 => (None, data),
      _ => {
        let (iv, data) = data.split_at(self.iv_len);
        (Some(iv), data)
      },
    };

    let plain = if self.is_aead {
      symm::decrypt_aead(self.cipher, &secret, iv, &self.aad, data, tag)
    } else {
      symm::decrypt(self.cipher, &secret, iv, data)
    }?;

    Ok(plain)
  }
}

impl<'a> Drop for Crypter<'a> {
  fn drop(&mut self) {
    self.key.zeroize();
  }
}

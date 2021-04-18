use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{ generic_array::GenericArray, Aead, NewAead, Payload };
use rand::{ thread_rng, RngCore };
use zeroize::Zeroize;

use crate::error::Error;

#[cfg(test)]
#[path = "./aes.test.rs"]
mod aes_test;

const IV_BYTES: usize   = 12;
const KEY_BYTES: u32    = 32;
const SALT_BYTES: usize = 16;

pub fn encrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
  let crypter = Crypter::new(key);
  crypter.encrypt(data)
}

pub fn decrypt(key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
  let crypter = Crypter::new(key);
  crypter.decrypt(data)
}

pub fn new(key: &[u8]) -> Crypter {
  Crypter::new(key)
}

pub struct Crypter<'a> {
  aad: Vec<u8>,
  key: Vec<u8>,
  config: argon2::Config<'a>,
}

impl<'a> Crypter<'a> {
  pub fn new(key: &[u8]) -> Self {
    let mut config = argon2::Config::default();
    config.hash_length = KEY_BYTES;

    Crypter {
      config,
      aad: Vec::new(),
      key: Vec::from(key),
    }
  }

  pub fn set_aad(&mut self, aad: &[u8]) {
    self.aad = aad.to_vec();
  }

  pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut iv = [0; IV_BYTES];
    thread_rng().fill_bytes(&mut iv);
    let nonce = GenericArray::from_slice(&iv);

    let mut salt = [0; SALT_BYTES];
    thread_rng().fill_bytes(&mut salt);
    let aeskey = argon2::hash_raw(&self.key, &salt, &self.config)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aeskey));

    let payload = Payload { msg: data, aad: &self.aad };
    let encrypted = cipher.encrypt(nonce, payload)?;

    let capacity = salt.len() + IV_BYTES + encrypted.len();
    let mut result: Vec<u8> = Vec::with_capacity(capacity);
    result.extend_from_slice(&salt);
    result.extend_from_slice(&iv);
    result.extend(encrypted);

    Ok(result)
  }

  pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let (salt, data) = data.split_at(SALT_BYTES);
    let (iv,   data) = data.split_at(IV_BYTES);

    let nonce  = GenericArray::from_slice(&iv);
    let aeskey = argon2::hash_raw(&self.key, &salt, &self.config)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&aeskey));

    let payload = Payload { msg: data, aad: &self.aad };
    let plain = cipher.decrypt(nonce, payload)?;

    Ok(plain)
  }
}

impl<'a> Drop for Crypter<'a> {
  fn drop(&mut self) {
    self.key.zeroize();
  }
}

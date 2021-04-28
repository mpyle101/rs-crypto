/** Timestamped Encryption */
use hmac::{Hmac, Mac, NewMac};
use openssl::memcmp;
use openssl::pkey::Private;
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::convert::TryInto;
use std::ops::DerefMut;
use std::time::SystemTime;
use zeroize::Zeroizing;

use crate::aes;
use crate::ecdh::Secret;
use crate::error::Error;
use crate::rsa::{self, PublicKey};

const DIGEST_BYTES: usize = 32;
const AESKEY_BYTES: usize = 32;
const ENCKEY_BYTES: usize = 256;
const WINDOW: u64 = 30;

pub fn new() -> Crypter {
  Crypter::new()
}

pub fn from(window: u64) -> Crypter {
  Crypter::from(window)
}

pub struct Crypter {
  window: u64,
}

impl Crypter {
  pub fn new() -> Self {
    Crypter { window: WINDOW }
  }

  pub fn from(window: u64) -> Self {
    Crypter { window }
  }

  pub fn encrypt(&self, pkey: &PublicKey, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with(pkey, secret, now()?, data)
  }

  pub fn decrypt(
    &self,
    crypter: &rsa::Crypter<Private>,
    secret: &Secret,
    data: &[u8],
  ) -> Result<Vec<u8>, Error> {
    decrypt_with(crypter, secret, now()?, self.window, data)
  }
}

type HmacSha256 = Hmac<Sha256>;

fn encrypt_with(
  pkey: &PublicKey,
  secret: &Secret,
  time: u64,
  data: &[u8],
) -> Result<Vec<u8>, Error> {
  let tsb = time.to_le_bytes();

  // Sign based on the secret and the timestamp
  let hkey = [&tsb, &secret as &[u8]].concat();
  let mut signer = HmacSha256::new_varkey(&hkey)?;
  signer.update(data);
  let digest = signer.finalize().into_bytes();

  let mut aeskey = Zeroizing::new(vec![0; AESKEY_BYTES]);
  thread_rng().fill_bytes(aeskey.deref_mut());
  let cipher = aes::encrypt(&aeskey, data)?;

  // Encrypt the AES key the timestamp bytes (LE) together
  let crypter = crate::rsa::from(pkey)?;
  let tsbkey = Zeroizing::new([&tsb, &aeskey as &[u8]].concat());
  let enckey = crypter.encrypt(&tsbkey)?;

  let capacity = digest.len() + enckey.len() + cipher.len();
  let mut result: Vec<u8> = Vec::with_capacity(capacity);
  result.extend(digest);
  result.extend(enckey);
  result.extend(cipher);

  Ok(result)
}

fn decrypt_with(
  crypter: &rsa::Crypter<Private>,
  secret: &Secret,
  time: u64,
  window: u64,
  data: &[u8],
) -> Result<Vec<u8>, Error> {
  let (digest, data) = data.split_at(DIGEST_BYTES);
  let (enckey, data) = data.split_at(ENCKEY_BYTES);

  // Timestamp bytes (LE) and AES key
  let tsbkey = Zeroizing::new(crypter.decrypt(enckey)?);
  let (tsval, aeskey) = tsbkey.split_at(8);

  // Check time window
  let tsb: [u8; 8] = tsval.try_into().or(Err(Error::BadTimeBytes))?;
  let ts = u64::from_le_bytes(tsb);
  if (ts < time - window) || (ts > time + window) {
    return Err(Error::BadTimeValue(ts));
  }
  let plain = aes::decrypt(aeskey, data)?;

  let hkey = [&tsb, &secret as &[u8]].concat();
  let mut signer = HmacSha256::new_varkey(&hkey)?;
  signer.update(&plain);
  let target = signer.finalize().into_bytes();
  if !memcmp::eq(digest, &target) {
    return Err(Error::DigestMismatch);
  }

  Ok(plain)
}

fn now() -> Result<u64, Error> {
  let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
  Ok(now.as_secs())
}

/** Unit Tests */
#[cfg(test)]
mod tests {
  use super::*;
  use crate::ecdh;
  use crate::rsa;

  #[test]
  fn it_works() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let rsacrp = rsa::new().unwrap();
    let pubkey = rsacrp.public_key().unwrap();

    let crypter = Crypter::new();
    let cipher = crypter.encrypt(&pubkey, &secret, data).unwrap();
    let plain = crypter.decrypt(&rsacrp, &secret, &cipher).unwrap();

    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }

  #[test]
  fn with_now() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let time = now().unwrap();
    let cipher = encrypt_with(&pubkey, &secret, time, data).unwrap();
    let plain = decrypt_with(&crypter, &secret, time, WINDOW, &cipher).unwrap();

    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }

  #[test]
  fn with_future() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let time = now().unwrap();
    let then = time + 30;
    let cipher = encrypt_with(&pubkey, &secret, time, data).unwrap();
    let plain = decrypt_with(&crypter, &secret, then, 30, &cipher).unwrap();

    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }

  #[test]
  fn with_past() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let time = now().unwrap();
    let then = time - 30;
    let cipher = encrypt_with(&pubkey, &secret, time, data).unwrap();
    let plain = decrypt_with(&crypter, &secret, then, 30, &cipher).unwrap();

    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }

  #[test]
  fn with_future_fails() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let time = now().unwrap();
    let then = time + 31;
    let cipher = encrypt_with(&pubkey, &secret, time, data).unwrap();
    let result = decrypt_with(&crypter, &secret, then, 30, &cipher);

    assert!(result.is_err());
  }

  #[test]
  fn with_past_fails() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let time = now().unwrap();
    let then = time - 31;
    let cipher = encrypt_with(&pubkey, &secret, time, data).unwrap();
    let result = decrypt_with(&crypter, &secret, then, 30, &cipher);

    assert!(result.is_err());
  }
}

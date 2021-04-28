/** Envelope Encryption */
use hmac::{Hmac, Mac, NewMac};
use openssl::memcmp;
use openssl::pkey::Private;
use rand::{thread_rng, RngCore};
use sha2::Sha256;
use std::ops::DerefMut;
use zeroize::Zeroizing;

use crate::aes;
use crate::ecdh::Secret;
use crate::error::Error;
use crate::rsa::{Crypter, PublicKey};

const DIGEST_BYTES: usize = 32;
const AESKEY_BYTES: usize = 32;
const ENCKEY_BYTES: usize = 256;

type HmacSha256 = Hmac<Sha256>;

pub fn encrypt(pkey: &PublicKey, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, Error> {
  let mut signer = HmacSha256::new_varkey(secret)?;
  signer.update(data);
  let digest = signer.finalize().into_bytes();

  let mut aeskey = Zeroizing::new([0u8; AESKEY_BYTES]);
  thread_rng().fill_bytes(aeskey.deref_mut());
  let cipher = aes::encrypt(aeskey.as_ref(), data)?;

  let crypter = crate::rsa::from(pkey);
  let enckey = crypter.encrypt(aeskey.as_ref())?;

  let capacity = digest.len() + enckey.len() + cipher.len();
  let mut result: Vec<u8> = Vec::with_capacity(capacity);
  result.extend(digest);
  result.extend(enckey);
  result.extend(cipher);

  Ok(result)
}

pub fn decrypt(crypter: &Crypter<Private>, secret: &Secret, data: &[u8]) -> Result<Vec<u8>, Error> {
  let (digest, data) = data.split_at(DIGEST_BYTES);
  let (enckey, data) = data.split_at(ENCKEY_BYTES);

  let aeskey = Zeroizing::new(crypter.decrypt(enckey)?);
  let plain = aes::decrypt(&aeskey, data)?;

  let mut signer = HmacSha256::new_varkey(secret)?;
  signer.update(&plain);
  let target = signer.finalize().into_bytes();
  if !memcmp::eq(digest, &target) {
    return Err(Error::DigestMismatch);
  }

  Ok(plain)
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
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let cipher = encrypt(&pubkey, &secret, data).unwrap();
    let plain = decrypt(&crypter, &secret, &cipher).unwrap();

    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }

  #[test]
  fn bad_digest() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let mut cipher = encrypt(&pubkey, &secret, data).unwrap();
    // Muck up the digest
    cipher[16] = cipher[16] ^ 255;
    let result = decrypt(&crypter, &secret, &cipher);

    assert!(result.is_err());
  }

  #[test]
  fn bad_aes_key() {
    let data = b"Some text to encrypt & decrypt";

    let server = ecdh::prime256v1().unwrap();
    let client = ecdh::prime256v1().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey = crypter.public_key().unwrap();

    let mut cipher = encrypt(&pubkey, &secret, data).unwrap();
    // Muck up the AES key
    cipher[37] = cipher[37] ^ 255;
    let result = decrypt(&crypter, &secret, &cipher);

    assert!(result.is_err());
  }
}

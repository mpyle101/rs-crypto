/** Envelope Encryption */

use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{ PKey, Private };
use openssl::sign::Signer;
use rand::{ thread_rng, RngCore };

use crate::aes;
use crate::ecdh::Secret;
use crate::error::Error;
use crate::rsa;

const DIGEST_BYTES: usize = 32;
const AESKEY_BYTES: usize = 32;
const ENCKEY_BYTES: usize = 256;

pub fn encrypt(
  pkey: &rsa::PublicKey,
  secret: &Secret,
  data: &[u8]
) -> Result<Vec<u8>, Error> {
  let hkey = PKey::hmac(secret)?;
  let mut signer = Signer::new(MessageDigest::sha256(), &hkey)?;
  signer.update(data)?;
  let digest = signer.sign_to_vec()?;

  let mut aeskey = vec![0; AESKEY_BYTES];
  thread_rng().fill_bytes(&mut aeskey);
  let cipher = aes::encrypt(&aeskey, data)?;

  let crypter = rsa::from(pkey)?;
  let enckey  = crypter.encrypt(&aeskey)?;

  let capacity = digest.len() + enckey.len() + cipher.len();
  let mut result: Vec<u8> = Vec::with_capacity(capacity);
  result.extend(digest);
  result.extend(enckey);
  result.extend(cipher);

  Ok(result)
}

pub fn decrypt(
  crypter: &rsa::Crypter<Private>,
  secret: &Secret,
  data: &[u8]
) -> Result<Vec<u8>, Error> {
  let (digest, data) = data.split_at(DIGEST_BYTES);
  let (enckey, data) = data.split_at(ENCKEY_BYTES);

  let aeskey = crypter.decrypt(enckey)?;
  let plain  = aes::decrypt(&aeskey, data)?;

  let hkey = PKey::hmac(secret)?;
  let mut signer = Signer::new(MessageDigest::sha256(), &hkey)?;
  signer.update(&plain)?;
  let target = signer.sign_to_vec()?;
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

  #[test]
  fn it_works() {
    let data = b"Some text to encrypt & decrypt";

    let server  = ecdh::prime256v1().unwrap();
    let client  = ecdh::prime256v1().unwrap();
    let pkey_c  = client.public_key().unwrap();
    let secret  = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey  = crypter.public_key().unwrap();

    let cipher = encrypt(&pubkey, &secret, data).unwrap();
    let plain  = decrypt(&crypter, &secret, &cipher).unwrap();
    
    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }

  #[test]
  fn bad_digest() {
    let data = b"Some text to encrypt & decrypt";

    let server  = ecdh::prime256v1().unwrap();
    let client  = ecdh::prime256v1().unwrap();
    let pkey_c  = client.public_key().unwrap();
    let secret  = server.compute(&pkey_c).unwrap();
    let crypter = rsa::new().unwrap();
    let pubkey  = crypter.public_key().unwrap();

    let mut cipher = encrypt(&pubkey, &secret, data).unwrap();
    // Muck up the digest
    cipher[16] = cipher[16] ^ 255;
    let result = decrypt(&crypter, &secret, &cipher);
    
    assert!(result.is_err());
  }
}
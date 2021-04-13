use openssl::hash::MessageDigest;
use openssl::pkey::{ PKey, Public, Private, HasPublic };
use openssl::rsa::{ Rsa, Padding };
use openssl::sign::{ Signer, Verifier };

use crate::error::Error;

const MODULOUS: u32 = 2048;
const PADDING: Padding = Padding::PKCS1_OAEP;

#[cfg(test)]
#[path = "./rsa.test.rs"]
mod rsa_test;

pub fn new() -> Result<Crypter<Private>, Error> {
  Crypter::<Private>::new()
}

pub fn from(pem: &str) -> Result<Crypter<Public>, Error> {
  Crypter::<Public>::from(pem)
}

pub struct Crypter<T: HasPublic> {
  key: Rsa<T>,
}

impl<T: HasPublic> Crypter<T> {
  pub fn new() -> Result<Crypter<Private>, Error> {
    Ok(Crypter {
      key: Rsa::generate(MODULOUS)?
    })
  }

  fn from(pem: &str) -> Result<Crypter<Public>, Error> {
    let key = if pem.contains("BEGIN PUBLIC") {
      Rsa::public_key_from_pem(pem.as_bytes())?
    } else {
      Rsa::public_key_from_pem_pkcs1(pem.as_bytes())?
    };

    Ok(Crypter { key })
  }
  
  pub fn to_pem(&self) -> Result<String, Error> {
    let pem = self.key.public_key_to_pem()?;
    Ok(String::from_utf8(pem)?)
  }

  pub fn to_pkcs1(&self) -> Result<String, Error> {
    let pem = self.key.public_key_to_pem_pkcs1()?;
    Ok(String::from_utf8(pem)?)
  }

  pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; self.key.size() as usize];
    let bytes = self.key.public_encrypt(data, &mut buf, PADDING)?;
    buf.truncate(bytes);

    Ok(buf)
  }

  pub fn verify(&self, signature: &[u8], data: &[u8]) -> Result<bool, Error> {
    let keypair = PKey::from_rsa(self.key.clone())?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair)?;
    verifier.update(data)?;

    Ok(verifier.verify(signature)?)
  }
}

impl Crypter<Private> {
  #[allow(dead_code)]
  fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; self.key.size() as usize];
    let bytes = self.key.private_decrypt(data, &mut buf, PADDING)?;
    buf.truncate(bytes);

    Ok(buf)
  }

  #[allow(dead_code)]
  fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let md = MessageDigest::sha256();
    let keypair = PKey::from_rsa(self.key.clone())?;
    let mut signer = Signer::new(md, &keypair)?;
    signer.update(data)?;

    Ok(signer.sign_to_vec()?)
  }
}

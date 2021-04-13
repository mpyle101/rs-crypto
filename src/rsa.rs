use openssl::hash::MessageDigest;
use openssl::pkey::{ PKey, Public, Private, HasPublic };
use openssl::rsa::{ Rsa, Padding };
use openssl::sign::{ Signer, Verifier };
use std::fmt;
use crate::error::Error;

const MODULOUS: u32 = 2048;
const PADDING: Padding = Padding::PKCS1_OAEP;

#[cfg(test)]
#[path = "./rsa.test.rs"]
mod rsa_test;

pub fn new() -> Result<Crypter<Private>, Error> {
  Crypter::<Private>::new()
}

pub fn from(key: PublicKey) -> Result<Crypter<Public>, Error> {
  Crypter::<Public>::from(key)
}

pub struct PublicKey {
  key: PKey<Public>,
}

impl PublicKey {
  pub fn new(pem: &[u8]) -> Result<Self, Error> {
    Ok(PublicKey { key: PKey::public_key_from_pem(pem)? })
  }

  pub fn from(pem: &str) -> Result<Self, Error> {
    let rsakey = if pem.contains("BEGIN PUBLIC") {
      Rsa::public_key_from_pem(pem.as_bytes())?
    } else {
      Rsa::public_key_from_pem_pkcs1(pem.as_bytes())?
    };

    Ok(PublicKey { key: PKey::from_rsa(rsakey)? })
  }

  pub fn to_pem(&self) -> Result<String, Error> {
    let pem = self.key.public_key_to_pem()?;
    Ok(String::from_utf8(pem)?)
  }
}

impl fmt::Display for PublicKey {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    let pem = self.key.public_key_to_pem()?;
    write!(f, "{:?}", pem)
  }
}

pub struct Crypter<T: HasPublic> {
  key: PKey<T>,
}

impl<T: HasPublic> Crypter<T> {
  pub fn new() -> Result<Crypter<Private>, Error> {
    let rsakey = Rsa::generate(MODULOUS)?;
    Ok(Crypter { key: PKey::from_rsa(rsakey)? })
  }

  fn from(public_key: PublicKey) -> Result<Crypter<Public>, Error> {
    Ok(Crypter { key: public_key.key })
  }
  
  pub fn public_key(&self) -> Result<PublicKey, Error> {
    let pem = self.key.public_key_to_pem()?;
    PublicKey::new(&pem)
  }

  pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let rsa = self.key.rsa()?;
    let mut buf = vec![0; self.key.size() as usize];
    let bytes = rsa.public_encrypt(data, &mut buf, PADDING)?;
    buf.truncate(bytes);

    Ok(buf)
  }

  pub fn verify(&self, signature: &[u8], data: &[u8]) -> Result<bool, Error> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), &self.key)?;
    verifier.update(data)?;

    Ok(verifier.verify(signature)?)
  }
}

impl Crypter<Private> {
  #[allow(dead_code)]
  fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let rsa = self.key.rsa()?;
    let mut buf = vec![0; self.key.size() as usize];
    let bytes = rsa.private_decrypt(data, &mut buf, PADDING)?;
    buf.truncate(bytes);

    Ok(buf)
  }

  #[allow(dead_code)]
  fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let md = MessageDigest::sha256();
    let mut signer = Signer::new(md, &self.key)?;
    signer.update(data)?;

    Ok(signer.sign_to_vec()?)
  }
}

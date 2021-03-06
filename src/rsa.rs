use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::{Signer, Verifier};

use crate::error::Error;

const MODULOUS: u32 = 2048;
const PADDING: Padding = Padding::PKCS1_OAEP;

#[cfg(test)]
#[path = "./rsa.test.rs"]
mod rsa_test;

pub fn new() -> Result<Crypter<Private>, Error> {
  Crypter::<Private>::with(MODULOUS)
}

pub fn from(key: &PublicKey) -> Crypter<Public> {
  Crypter::<Public>::from(&key)
}

pub struct PublicKey {
  key: PKey<Public>,
}

impl PublicKey {
  pub fn new(pem: &[u8]) -> Result<Self, Error> {
    let rsakey = Rsa::public_key_from_pem(pem)?;
    Ok(PublicKey {
      key: PKey::from_rsa(rsakey)?,
    })
  }

  pub fn from(pem: &str) -> Result<Self, Error> {
    let rsakey = if pem.contains("BEGIN PUBLIC") {
      Rsa::public_key_from_pem(pem.as_bytes())?
    } else {
      Rsa::public_key_from_pem_pkcs1(pem.as_bytes())?
    };

    Ok(PublicKey {
      key: PKey::from_rsa(rsakey)?,
    })
  }

  pub fn to_pem(&self) -> Result<String, Error> {
    let key = self.key.rsa()?;
    let pem = key.public_key_to_pem()?;
    Ok(String::from_utf8(pem)?)
  }
}

pub struct Crypter<T: HasPublic> {
  key: PKey<T>,
}

impl<T: HasPublic> Crypter<T> {
  pub fn with(modulous: u32) -> Result<Crypter<Private>, Error> {
    let rsakey = Rsa::generate(modulous)?;
    Ok(Crypter {
      key: PKey::from_rsa(rsakey)?,
    })
  }

  fn from(public_key: &PublicKey) -> Crypter<Public> {
    Crypter {
      key: public_key.key.clone(),
    }
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
  pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let rsa = self.key.rsa()?;
    let mut buf = vec![0; self.key.size() as usize];
    let bytes = rsa.private_decrypt(data, &mut buf, PADDING)?;
    buf.truncate(bytes);

    Ok(buf)
  }

  pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let md = MessageDigest::sha256();
    let mut signer = Signer::new(md, &self.key)?;
    signer.update(data)?;

    Ok(signer.sign_to_vec()?)
  }
}

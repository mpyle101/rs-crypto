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

pub fn new() -> Result<Crypter, Error> {
  Crypter::new()
}

#[derive(Clone)]
pub enum Key {
  Public(Rsa<Public>),
  Private(Rsa<Private>),
}

impl Key {
  fn size(&self) -> usize {
    match self {
      Key::Public(key)  => key.size() as usize,
      Key::Private(key) => key.size() as usize,
    }
  }

  pub fn to_pem(&self) -> Result<String, Error> {
    let pem = match &self {
      Key::Public(key)  => key.public_key_to_pem(),
      Key::Private(key) => key.public_key_to_pem(),
    }?;

    Ok(String::from_utf8(pem)?)
  }

  pub fn to_pkcs1(&self) -> Result<String, Error> {
    let pem = match &self {
      Key::Public(key)  => key.public_key_to_pem_pkcs1(),
      Key::Private(key) => key.public_key_to_pem_pkcs1(),
    }?;

    Ok(String::from_utf8(pem)?)
  }
}

pub struct Crypter {
  key: Key,
}

impl Crypter {
  pub fn new() -> Result<Self, Error> {
    Ok(Crypter {
      key: Key::Private(Rsa::generate(MODULOUS)?)
    })
  }

  pub fn from(pem: &str) -> Result<Self, Error> {
    let key = if pem.contains("BEGIN PUBLIC") {
      Rsa::public_key_from_pem(pem.as_bytes())?
    } else {
      Rsa::public_key_from_pem_pkcs1(pem.as_bytes())?
    };

    Ok(Crypter { key: Key::Public(key) })
  }
  
  pub fn get(&self) -> Key {
    self.key.clone()
  }

  pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; self.key.size()];
    let bytes = match &self.key {
      Key::Public(key)  => key.public_encrypt(data, &mut buf, PADDING),
      Key::Private(key) => key.public_encrypt(data, &mut buf, PADDING),
    }?;
    buf.truncate(bytes);

    Ok(buf)
  }

  pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0; self.key.size()];
    let bytes = match &self.key {
      Key::Public(_)    => return Err(Error::RsaPublicKey),
      Key::Private(key) => key.private_decrypt(data, &mut buf, PADDING)?,
    };
    buf.truncate(bytes);

    Ok(buf)
  }

  pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
    let md = MessageDigest::sha256();
    let signature = match &self.key {
      Key::Public(_)    => return Err(Error::RsaPublicKey),
      Key::Private(key) => {
        let keypair = PKey::from_rsa(key.clone())?;
        let mut signer = Signer::new(md, &keypair)?;
        signer.update(data)?;
        signer.sign_to_vec()?
      },
    };

    Ok(signature)
  }

  pub fn verify(&self, signature: &[u8], data: &[u8]) -> Result<bool, Error> {
    let result = match &self.key {
      Key::Public(key)  => verify(&key, signature, data),
      Key::Private(key) => verify(&key, signature, data),
    }?;

    Ok(result)
  }
}

fn verify<T: HasPublic>(
  key: &Rsa<T>,
  signature: &[u8],
  data: &[u8]
) -> Result<bool, Error> {
  let keypair = PKey::from_rsa(key.clone())?;
  let mut verifier = Verifier::new(MessageDigest::sha256(), &keypair)?;
  verifier.update(data)?;
  let result = verifier.verify(signature)?;

  Ok(result)
}

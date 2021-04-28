use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use std::ops::Deref;

use crate::error::Error;

pub fn prime256v1() -> Result<Crypter, Error> {
  Crypter::from(Nid::X9_62_PRIME256V1)
}
pub fn secp384r1() -> Result<Crypter, Error> {
  Crypter::from(Nid::SECP384R1)
}
pub fn secp521r1() -> Result<Crypter, Error> {
  Crypter::from(Nid::SECP521R1)
}

#[derive(Debug)]
pub struct PublicKey {
  key: PKey<Public>,
}

impl PublicKey {
  pub fn new(pem: &[u8]) -> Result<Self, Error> {
    let eckey = EcKey::public_key_from_pem(pem)?;
    Ok(PublicKey {
      key: PKey::from_ec_key(eckey)?,
    })
  }

  pub fn from(pem: &str) -> Result<Self, Error> {
    let eckey = EcKey::public_key_from_pem(pem.as_bytes())?;
    Ok(PublicKey {
      key: PKey::from_ec_key(eckey)?,
    })
  }

  pub fn to_pem(&self) -> Result<String, Error> {
    let key = self.key.ec_key()?;
    let pem = key.public_key_to_pem()?;
    Ok(String::from_utf8(pem)?)
  }
}

impl PartialEq for PublicKey {
  fn eq(&self, other: &Self) -> bool {
    let pem1 = match self.key.public_key_to_pem() {
      Ok(pem) => pem,
      Err(_) => return false,
    };
    let pem2 = match other.key.public_key_to_pem() {
      Ok(pem) => pem,
      Err(_) => return false,
    };
    pem1 == pem2
  }
}

#[derive(Debug, PartialEq)]
pub struct Secret {
  secret: Vec<u8>,
}

impl Deref for Secret {
  type Target = [u8];

  fn deref(&self) -> &Self::Target {
    return &self.secret;
  }
}

pub struct Crypter {
  key: PKey<Private>,
}

impl Crypter {
  pub fn new() -> Result<Self, Error> {
    Crypter::from(Nid::X9_62_PRIME256V1)
  }

  fn from(nid: Nid) -> Result<Self, Error> {
    let group = EcGroup::from_curve_name(nid)?;
    let eckey = EcKey::generate(&group)?;
    Ok(Crypter {
      key: PKey::from_ec_key(eckey)?,
    })
  }

  pub fn public_key(&self) -> Result<PublicKey, Error> {
    let pem = self.key.public_key_to_pem()?;
    PublicKey::new(&pem)
  }

  pub fn compute(&self, peer: &PublicKey) -> Result<Secret, Error> {
    let mut deriver = Deriver::new(&self.key)?;
    deriver.set_peer(&peer.key)?;
    Ok(Secret {
      secret: deriver.derive_to_vec()?,
    })
  }
}

/** Unit Tests */
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let server = Crypter::new().unwrap();
    let client = Crypter::new().unwrap();
    let pkey_s = server.public_key().unwrap();
    let pkey_c = client.public_key().unwrap();
    let secret_s = server.compute(&pkey_c).unwrap();
    let secret_c = client.compute(&pkey_s).unwrap();

    assert_ne!(pkey_s, pkey_c);
    assert_eq!(secret_s, secret_c);
  }
}

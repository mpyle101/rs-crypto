use openssl::derive::Deriver;
use openssl::ec::{ EcGroup, EcKey };
use openssl::nid::Nid;
use openssl::pkey::{ PKey, Private };

use crate::error::Error;

pub struct Crypter {
  key: PKey<Private>,
}

impl Crypter {
  pub fn new() -> Result<Self, Error> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let eckey = EcKey::generate(&group)?;

    Ok(Crypter { key: PKey::from_ec_key(eckey)? })
  }
  
  pub fn public_key(&self) -> Result<String, Error> {
    let pem = self.key.public_key_to_pem()?;
    Ok(String::from_utf8(pem)?)
  }

  pub fn compute(&self, pem: &str) -> Result<Vec<u8>, Error> {
    let pkey = PKey::public_key_from_pem(pem.as_bytes())?;
    let mut deriver = Deriver::new(&self.key)?;
    deriver.set_peer(&pkey)?;
    
    Ok(deriver.derive_to_vec()?)
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

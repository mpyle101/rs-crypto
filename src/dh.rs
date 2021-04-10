use openssl::bn::BigNumRef;
use openssl::dh::Dh;
use openssl::pkey::Private;

use crate::error::Error;

#[derive(Debug, PartialEq)]
pub struct PublicKey<'a> {
  bn: &'a BigNumRef,
}

pub struct Crypter {
  key: Dh<Private>,
}

impl Crypter {
  pub fn new() -> Result<Self, Error> {
    let dh = Dh::get_2048_256()?;
    Ok(Crypter { key: dh.generate_key()? })
  }
  
  pub fn public_key(&self) -> PublicKey {
    PublicKey { bn: self.key.public_key() }
  }

  pub fn compute(&self, key: &PublicKey) -> Result<Vec<u8>, Error> {
    Ok(self.key.compute_key(key.bn)?)
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
    let pkey_s = server.public_key();
    let pkey_c = client.public_key();
    let secret_s = server.compute(&pkey_c).unwrap();
    let secret_c = client.compute(&pkey_s).unwrap();
    
    assert_ne!(pkey_s, pkey_c);
    assert_eq!(secret_s, secret_c);
  }
}

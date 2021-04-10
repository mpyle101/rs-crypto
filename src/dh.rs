use openssl::base64;
use openssl::bn::BigNum;
use openssl::dh::Dh;
use openssl::pkey::Private;

use crate::error::Error;

#[derive(Debug, PartialEq)]
pub struct PublicKey {
  bn: BigNum,
}

impl PublicKey {
  pub fn from(src: &str) -> Result<Self, Error> {
    let v = base64::decode_block(src)?;
    Ok(PublicKey{
      bn: BigNum::from_slice(&v)?
    })
  }

  pub fn to_base64(&self) -> String {
    base64::encode_block(&self.bn.to_vec())
  }
}

pub struct Crypter {
  key: Dh<Private>,
}

impl Crypter {
  pub fn new() -> Result<Self, Error> {
    let dh = Dh::get_2048_256()?;
    Ok(Crypter { key: dh.generate_key()? })
  }
  
  pub fn public_key(&self) -> Result<PublicKey, Error> {
    Ok(PublicKey { 
      bn: BigNum::from_slice(&self.key.public_key().to_vec())?
    })
  }

  pub fn compute(&self, key: &PublicKey) -> Result<Vec<u8>, Error> {
    Ok(self.key.compute_key(&key.bn)?)
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

  #[test]
  fn base64() {
    let server = Crypter::new().unwrap();
    let client = Crypter::new().unwrap();
    let pkey_s = server.public_key().unwrap();
    let pkey_c = client.public_key().unwrap();

    let public_s = PublicKey::from(&pkey_s.to_base64()).unwrap();
    let public_c = PublicKey::from(&pkey_c.to_base64()).unwrap();
    let secret_s = server.compute(&public_c).unwrap();
    let secret_c = client.compute(&public_s).unwrap();
    
    assert_ne!(pkey_s, pkey_c);
    assert_eq!(secret_s, secret_c);
  }
}

#[cfg(test)]
mod tests {
  use crate::rsa::Rsa;

  #[test]
  fn it_works() {
    let data    = b"Some secrets to encrypt";
    let crypter = Rsa::new().unwrap();
    let cipher  = crypter.encrypt(data).unwrap();
    let plain   = crypter.decrypt(&cipher).unwrap();
    
    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn decrypt_by_pem() {
    let data   = b"Some secrets to encrypt";
    let server = Rsa::new().unwrap();
    let pem    = server.to_pem().unwrap();
    let client = Rsa::from(&pem).unwrap();
    let cipher = client.encrypt(data).unwrap();
    let plain  = server.decrypt(&cipher).unwrap();
    
    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn decrypt_by_pkcs1() {
    let data   = b"Some secrets to encrypt";
    let server = Rsa::new().unwrap();
    let pem    = server.to_pkcs1().unwrap();
    let client = Rsa::from(&pem).unwrap();
    let cipher = client.encrypt(data).unwrap();
    let plain  = server.decrypt(&cipher).unwrap();
    
    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn signing() {
    let data    = b"Some text to verify";
    let crypter = Rsa::new().unwrap();
    let signed  = crypter.sign(data).unwrap();
    
    assert!(crypter.verify(&signed, data).unwrap());
  }

  #[test]
  fn signing_by_pem() {
    let data   = b"Some text to verify";
    let server = Rsa::new().unwrap();
    let pem    = server.to_pem().unwrap();
    let client = Rsa::from(&pem).unwrap();
    let signed = server.sign(data).unwrap();
    
    assert!(client.verify(&signed, data).unwrap());
  }

  #[test]
  fn signing_by_pkcs1() {
    let data   = b"Some text to verify";
    let server = Rsa::new().unwrap();
    let pem    = server.to_pkcs1().unwrap();
    let client = Rsa::from(&pem).unwrap();
    let signed = server.sign(data).unwrap();
    
    assert!(client.verify(&signed, data).unwrap());
  }
}

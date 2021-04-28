#[cfg(test)]
mod tests {
  use crate::rsa;

  #[test]
  fn it_works() {
    let data = b"Some secrets to encrypt & decrypt";
    let crypter = rsa::new().unwrap();
    let cipher = crypter.encrypt(data).unwrap();
    let plain = crypter.decrypt(&cipher).unwrap();

    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn decrypt_by_public_key() {
    let data = b"Some secrets to encrypt & decrypt";
    let server = rsa::new().unwrap();
    let pkey_s = server.public_key().unwrap();
    let client = rsa::from(&pkey_s).unwrap();

    let cipher = client.encrypt(data).unwrap();
    let plain = server.decrypt(&cipher).unwrap();

    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn decrypt_by_public_pem() {
    let data = b"Some secrets to encrypt & decrypt";
    let server = rsa::new().unwrap();
    let pkey_s = server.public_key().unwrap();
    let pem = pkey_s.to_pem().unwrap();
    let pemkey = rsa::PublicKey::from(&pem).unwrap();
    let client = rsa::from(&pemkey).unwrap();

    let cipher = client.encrypt(data).unwrap();
    let plain = server.decrypt(&cipher).unwrap();

    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn signing() {
    let data = b"Some text to sign & verify";
    let crypter = rsa::new().unwrap();
    let signed = crypter.sign(data).unwrap();

    assert!(crypter.verify(&signed, data).unwrap());
  }

  #[test]
  fn signing_by_public_key() {
    let data = b"Some text to sign & verify";
    let server = rsa::new().unwrap();
    let pkey_s = server.public_key().unwrap();
    let client = rsa::from(&pkey_s).unwrap();
    let signed = server.sign(data).unwrap();

    assert!(client.verify(&signed, data).unwrap());
  }

  #[test]
  fn signing_by_public_pem() {
    let data = b"Some text to sign & verify";
    let server = rsa::new().unwrap();
    let pkey_s = server.public_key().unwrap();
    let pem = pkey_s.to_pem().unwrap();
    let pemkey = rsa::PublicKey::from(&pem).unwrap();
    let client = rsa::from(&pemkey).unwrap();
    let signed = server.sign(data).unwrap();

    assert!(client.verify(&signed, data).unwrap());
  }
}

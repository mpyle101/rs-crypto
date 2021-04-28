#[cfg(test)]
mod tests {
  use crate::aes;

  #[test]
  fn it_works() {
    // Default configuration
    let data = b"Some secrets to encrypt";
    let crypter = aes::Crypter::new(b"My password");
    let cipher = crypter.encrypt(data).unwrap();
    let plain = crypter.decrypt(&cipher).unwrap();

    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn module_new() {
    let data = b"Some secrets to encrypt";
    let crypter = aes::new(b"Secret password");
    let cipher = crypter.encrypt(data).unwrap();
    let plain = crypter.decrypt(&cipher).unwrap();

    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn authenticated_with_aad() {
    let data = b"Some secrets to encrypt";
    let mut crypter = aes::new(b"Secret password");
    crypter.set_aad(b"Additional authentication data");
    let cipher = crypter.encrypt(data).unwrap();
    let plain = crypter.decrypt(&cipher).unwrap();

    assert_eq!(data, &plain[..]);
    assert_ne!(data, &cipher[..]);
  }

  #[test]
  fn authenticated_with_bad_aad() {
    let data = b"Some secrets to encrypt";
    let mut crypter = aes::new(b"Secret password");

    crypter.set_aad(b"Additional authentication data");
    let cipher = crypter.encrypt(data).unwrap();

    crypter.set_aad(b"Bad authentication data");
    let result = crypter.decrypt(&cipher);

    assert!(result.is_err());
  }

  #[test]
  fn authenticated_with_bad_cipher() {
    let data = b"Some secrets to encrypt";
    let mut crypter = aes::new(b"Secret password");

    crypter.set_aad(b"Additional authentication data");
    let mut cipher = crypter.encrypt(data).unwrap();

    // Make sure the byte is changed
    cipher[16] = cipher[16] ^ 255;
    let result = crypter.decrypt(&cipher);

    assert!(result.is_err());
  }
}

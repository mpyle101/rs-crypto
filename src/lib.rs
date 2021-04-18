pub mod aes;
pub mod evp;
pub mod ecdh;
pub mod rsa;
pub mod tse;
pub mod error;

pub use aes::encrypt as aes_encrypt;
pub use aes::decrypt as aes_decrypt;
pub use ecdh::prime256v1 as create_ecdh;
pub use evp::{ encrypt, decrypt };
pub use rsa::new as create_rsa;


/** Unit Tests */
#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn it_works() {
    let data = b"Some text to encrypt & decrypt";

    let server  = create_ecdh().unwrap();
    let client  = create_ecdh().unwrap();
    let pkey_c  = client.public_key().unwrap();
    let secret  = server.compute(&pkey_c).unwrap();
    let crypter = create_rsa().unwrap();
    let pubkey  = crypter.public_key().unwrap();

    let cipher = encrypt(&pubkey, &secret, data).unwrap();
    let plain  = decrypt(&crypter, &secret, &cipher).unwrap();
    
    assert_ne!(cipher, plain);
    assert_eq!(plain, data);
  }
}
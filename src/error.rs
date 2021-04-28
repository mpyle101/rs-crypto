use aes_gcm;
use argon2;
use hmac::crypto_mac::InvalidKeyLength;
use openssl::error::ErrorStack;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;

#[derive(Debug)]
pub enum Error {
  AesGcm(aes_gcm::Error),
  Argon2(argon2::Error),
  OpenSSL(ErrorStack),
  Stringify(FromUtf8Error),
  SystemTime(SystemTimeError),
  BadDigest(InvalidKeyLength),
  RsaPublicKey,
  DigestMismatch,
  BadTimeBytes,
  BadTimeValue(u64),
}

impl From<ErrorStack> for Error {
  fn from(e: ErrorStack) -> Error {
    Error::OpenSSL(e)
  }
}

impl From<aes_gcm::Error> for Error {
  fn from(e: aes_gcm::Error) -> Error {
    Error::AesGcm(e)
  }
}

impl From<argon2::Error> for Error {
  fn from(e: argon2::Error) -> Error {
    Error::Argon2(e)
  }
}

impl From<FromUtf8Error> for Error {
  fn from(e: FromUtf8Error) -> Error {
    Error::Stringify(e)
  }
}

impl From<SystemTimeError> for Error {
  fn from(e: SystemTimeError) -> Error {
    Error::SystemTime(e)
  }
}

impl From<InvalidKeyLength> for Error {
  fn from(e: InvalidKeyLength) -> Error {
    Error::BadDigest(e)
  }
}

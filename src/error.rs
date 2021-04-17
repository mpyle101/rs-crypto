use argon2;
use openssl::error::ErrorStack;
use std::string::FromUtf8Error;
use std::time::SystemTimeError;

#[derive(Debug)]
pub enum Error {
  Argon2(argon2::Error),
  OpenSSL(ErrorStack),
  Stringify(FromUtf8Error),
  SystemTime(SystemTimeError),
  RsaPublicKey,
  DigestMismatch,
  BadTimeBytes,
  BadTimeValue(u64)
}

impl From<ErrorStack> for Error {
  fn from(e: ErrorStack) -> Error {
    Error::OpenSSL(e)
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
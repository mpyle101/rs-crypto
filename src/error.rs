use argon2;
use openssl::error::ErrorStack;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum Error {
  Argon2(argon2::Error),
  OpenSSL(ErrorStack),
  PEM(FromUtf8Error),
  RsaPublicKey,
  DigestMismatch,
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
    Error::PEM(e)
  }
}
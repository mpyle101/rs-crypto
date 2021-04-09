use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key {
  value: Vec<u8>
}

impl Key {
  pub fn from(key: &[u8]) -> Key {
    Key { value: Vec::from(key) }
  }

  pub fn as_bytes(&self) -> &[u8] {
    &self.value
  }
}

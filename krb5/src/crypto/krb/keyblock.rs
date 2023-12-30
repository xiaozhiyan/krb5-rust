use super::Enctype;

#[derive(Debug)]
pub struct Keyblock {
    pub enctype: Enctype,
    pub contents: Vec<u8>,
}

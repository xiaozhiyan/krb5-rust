const REALM_SEP: u8 = b'@';
const COMPONENT_SEP: u8 = b'/';

#[derive(Debug)]
pub struct Principal {
    pub realm: Vec<u8>,
    pub components: Vec<Vec<u8>>,
    pub r#type: i32,
}

impl Principal {
    pub fn unparse_name(&self) -> anyhow::Result<String> {
        // TODO: flags `KRB5_PRINCIPAL_UNPARSE_SHORT`, `KRB5_PRINCIPAL_UNPARSE_NO_REALM`
        let name = self
            .components
            .iter()
            .map(|component| component.clone())
            .collect::<Vec<Vec<u8>>>()
            .join(&COMPONENT_SEP);
        let realm = self.realm.clone();
        let name = vec![name, realm].join(&REALM_SEP);
        Ok(String::from_utf8(name)?)
    }
}

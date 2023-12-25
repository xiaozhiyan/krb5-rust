use crate::Principal;

const REALM_SEP: u8 = b'@';
const COMPONENT_SEP: u8 = b'/';

pub fn unparse_name(principal: &Principal) -> anyhow::Result<String> {
    // TODO: flags `KRB5_PRINCIPAL_UNPARSE_SHORT`, `KRB5_PRINCIPAL_UNPARSE_NO_REALM`
    let name = principal
        .components
        .iter()
        .map(|component| component.clone())
        .collect::<Vec<Vec<u8>>>()
        .join(&COMPONENT_SEP);
    let realm = principal.realm.clone();
    let name = vec![name, realm].join(&REALM_SEP);
    Ok(String::from_utf8(name)?)
}

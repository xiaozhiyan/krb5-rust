use crate::{Address, AuthData, Enctype, Flags, Keyblock, Kvno, NameType, Principal, TicketTimes};
use der_parser::{
    asn1_rs::{self, Any, CheckDerConstraints, DerAutoDerive, FromDer},
    ber::BerObjectContent,
    der::{
        parse_der_generalstring, parse_der_i32, parse_der_octetstring, parse_der_sequence,
        parse_der_u32, Tag,
    },
};

#[derive(Debug)]
pub struct Ticket {
    pub server: Principal,
    pub enc_part: EncData,
    pub enc_part2: Vec<EncTktPart>,
}

impl<'a> TryFrom<Any<'a>> for Ticket {
    type Error = asn1_rs::Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        let (_, seq) = parse_der_sequence(any.data)?;
        let seq = seq.as_sequence()?;
        if seq.len() != 4 {
            Err(asn1_rs::Error::BerValueError)?
        }

        let _version = match &seq[0].content {
            BerObjectContent::Unknown(content) => {
                let (_, version) = parse_der_i32(content.data)?;
                version
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };

        let realm = match &seq[1].content {
            BerObjectContent::Unknown(content) => {
                let (_, realm) = parse_der_generalstring(content.data)?;
                realm.as_str()?
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };

        let principal = match &seq[2].content {
            BerObjectContent::Unknown(content) => {
                let (_, principal) = parse_der_sequence(content.data)?;
                principal
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };
        let principal = principal.as_sequence()?;
        if principal.len() != 2 {
            Err(asn1_rs::Error::BerValueError)?
        }
        let component_count = match &principal[0].content {
            BerObjectContent::Unknown(content) => {
                let (_, component_count) = parse_der_i32(content.data)?;
                component_count
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };
        let components = match &principal[1].content {
            BerObjectContent::Unknown(content) => {
                let (_, components) = parse_der_sequence(content.data)?;
                components
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };
        let components = components.as_sequence()?;
        if components.len() != component_count as usize {
            Err(asn1_rs::Error::BerValueError)?
        }
        let mut principal_components = vec![];
        for component in components {
            principal_components.push(component.as_str()?.as_bytes().to_owned());
        }

        let encrypted_data = match &seq[3].content {
            BerObjectContent::Unknown(content) => {
                let (_, encrypted_data) = parse_der_sequence(content.data)?;
                encrypted_data
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };
        let encrypted_data = encrypted_data.as_sequence()?;
        if encrypted_data.len() != 3 {
            Err(asn1_rs::Error::BerValueError)?
        }

        let enctype = match &encrypted_data[0].content {
            BerObjectContent::Unknown(content) => {
                let (_, enctype) = parse_der_i32(content.data)?;
                Enctype(enctype)
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };

        let kvno = match &encrypted_data[1].content {
            BerObjectContent::Unknown(content) => {
                let (_, kvno) = parse_der_u32(content.data)?;
                kvno
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };

        let ciphertext = match &encrypted_data[encrypted_data.len() - 1].content {
            BerObjectContent::Unknown(content) => {
                let (_, ciphertext) = parse_der_octetstring(content.data)?;
                ciphertext
            }
            _ => Err(asn1_rs::Error::BerValueError)?,
        };
        let ciphertext = match ciphertext.content {
            BerObjectContent::OctetString(content) => content,
            _ => Err(asn1_rs::Error::BerValueError)?,
        };

        Ok(Ticket {
            server: Principal {
                realm: realm.as_bytes().to_owned(),
                components: principal_components,
                name_type: NameType::PRINCIPAL,
            },
            enc_part: EncData {
                enctype,
                kvno,
                ciphertext: ciphertext.to_owned(),
            },
            enc_part2: vec![],
        })
    }
}

impl CheckDerConstraints for Ticket {
    fn check_constraints(any: &Any) -> asn1_rs::Result<()> {
        any.header.assert_class(asn1_rs::Class::Application)?;
        any.header.assert_constructed()?;
        any.header.assert_tag(Tag::Boolean)?;
        Ok(())
    }
}

impl DerAutoDerive for Ticket {}

impl Ticket {
    pub fn decode_from(data: &Vec<u8>) -> anyhow::Result<Self> {
        let (_, ticket) = Self::from_der(data)?;
        Ok(ticket)
    }
}

#[derive(Debug)]
pub struct EncData {
    pub enctype: Enctype,
    pub kvno: Kvno,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct EncTktPart {
    pub flags: Flags,
    pub session: Vec<Keyblock>,
    pub client: Principal,
    pub transited: Transited,
    pub times: TicketTimes,
    pub caddrs: Vec<Address>,
    pub authorization_data: Vec<AuthData>,
}

#[derive(Debug)]
pub struct Transited {
    pub tr_type: u8,
    pub tr_contents: Vec<u8>,
}

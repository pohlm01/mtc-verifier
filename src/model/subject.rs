use crate::model::{Decode, Encode, Hashable, PayloadU16, SignatureScheme};
use nom::number::complete::u16;
use nom::IResult;
use sha2::Digest;

#[derive(Debug, Clone)]
pub enum Subject<'a> {
    Tls(TLSSubjectInfo<'a>),
    Unknown,
}

#[derive(Debug, Clone)]
pub struct TLSSubjectInfo<'a> {
    signature: SignatureScheme,
    public_key: PayloadU16<'a>,
}

impl<'a> Decode<'a> for TLSSubjectInfo<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, signature) = SignatureScheme::decode(input)?;
        let (bytes, public_key) = PayloadU16::decode(bytes)?;
        Ok((
            bytes,
            Self {
                signature,
                public_key,
            },
        ))
    }
}

impl Encode for TLSSubjectInfo<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.signature.encode();
        bytes.extend_from_slice(&self.public_key.encode());
        bytes
    }
}

impl Hashable for TLSSubjectInfo<'_> {}

impl TLSSubjectInfo<'_> {
    pub(super) fn hash<D: Digest>(&self) -> Vec<u8> {
        D::digest(self.encode()).to_vec()
    }
}

#[derive(Debug)]
pub(super) enum SubjectType {
    Tls,
    Unknown,
}

impl Decode<'_> for SubjectType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::Tls,
            _ => Self::Unknown,
        };
        Ok((bytes, claim))
    }
}

impl Encode for SubjectType {
    fn encode(&self) -> Vec<u8> {
        match self {
            SubjectType::Tls => {
                vec![0, 0]
            }
            SubjectType::Unknown => {
                unimplemented!()
            }
        }
    }
}

use crate::model::{Decode, PayloadU16, SignatureScheme};
use nom::number::complete::u16;
use nom::IResult;

#[derive(Debug)]
pub enum Subject<'a> {
    Tls(TLSSubjectInfo<'a>),
    Unknown,
}

#[derive(Debug)]
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

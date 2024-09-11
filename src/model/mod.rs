mod assertion;
mod certificate;
mod claim;
mod proof;
mod subject;
mod trust_anchor_identifier;

use nom::bytes::complete::take;
use nom::number::complete::{u16, u8};
use nom::IResult;
use std::fmt::{Debug, Formatter};

pub use assertion::Assertion;
pub use certificate::Certificate;
pub use claim::Claim;
pub use proof::Proof;
pub use subject::{Subject, TLSSubjectInfo};
pub use trust_anchor_identifier::TrustAnchorIdentifier;

trait Decode<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self>
    where
        Self: Sized;
}

impl<'a, T: Decode<'a> + Sized> Decode<'a> for Vec<T> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = u16(nom::number::Endianness::Big)(input)?;
        let mut vec = Vec::new();
        let mut vec_bytes = &bytes[0..length as usize];
        while !vec_bytes.is_empty() {
            let item;
            (vec_bytes, item) = T::decode(vec_bytes)?;
            vec.push(item);
        }
        Ok((&bytes[length as usize..], vec))
    }
}

pub struct HashValueSHA256<'a>(pub &'a [u8; 32]);

impl<'a> Decode<'a> for HashValueSHA256<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, sha) = take(32usize)(input)?;
        // TODO remove `expect()`
        Ok((
            bytes,
            Self(sha.try_into().expect("sha256 did expect more data")),
        ))
    }
}

impl Debug for HashValueSHA256<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SHA256({:x?})", self.0)
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum SignatureScheme {
    RSA_PKCS1_SHA1,
    ECDSA_SHA1_Legacy,
    RSA_PKCS1_SHA256,
    ECDSA_NISTP256_SHA256,
    RSA_PKCS1_SHA384,
    ECDSA_NISTP384_SHA384,
    RSA_PKCS1_SHA512,
    ECDSA_NISTP521_SHA512,
    RSA_PSS_SHA256,
    RSA_PSS_SHA384,
    RSA_PSS_SHA512,
    ED25519,
    ED448,
    Unknown,
}

impl<'a> Decode<'a> for SignatureScheme {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, code) = u16(nom::number::Endianness::Big)(input)?;
        let sig = match code {
            0x0201 => Self::RSA_PKCS1_SHA1,
            0x0203 => Self::ECDSA_SHA1_Legacy,
            0x0401 => Self::RSA_PKCS1_SHA256,
            0x0403 => Self::ECDSA_NISTP256_SHA256,
            0x0501 => Self::RSA_PKCS1_SHA384,
            0x0503 => Self::ECDSA_NISTP384_SHA384,
            0x0601 => Self::RSA_PKCS1_SHA512,
            0x0603 => Self::ECDSA_NISTP521_SHA512,
            0x0804 => Self::RSA_PSS_SHA256,
            0x0805 => Self::RSA_PSS_SHA384,
            0x0806 => Self::RSA_PSS_SHA512,
            0x0807 => Self::ED25519,
            0x0808 => Self::ED448,
            _ => Self::Unknown,
        };
        Ok((bytes, sig))
    }
}

pub struct PayloadU16<'a>(pub &'a [u8]);

impl<'a> Decode<'a> for PayloadU16<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = u16(nom::number::Endianness::Big)(input)?;
        let (bytes, payload) = take(length)(bytes)?;
        Ok((bytes, PayloadU16(payload)))
    }
}

impl Debug for PayloadU16<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

pub struct PayloadU8<'a>(pub &'a [u8]);

impl<'a> Decode<'a> for PayloadU8<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = u8(input)?;
        let (bytes, payload) = take(length)(bytes)?;
        Ok((bytes, PayloadU8(payload)))
    }
}

impl Debug for PayloadU8<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn basic() {
        let bytes = include_bytes!("../../assets/my-cert-tai");
        dbg!(Certificate::decode(bytes).unwrap());

        let bytes = include_bytes!("../../assets/my-cert-big-tai");
        dbg!(Certificate::decode(bytes).unwrap());
    }
}

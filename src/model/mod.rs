pub(crate) mod assertion;
pub(crate) mod certificate;
pub(crate) mod claim;
pub(crate) mod proof;
pub(crate) mod subject;
pub(crate) mod tai_store;
pub(crate) mod tree;
pub(crate) mod trust_anchor_identifier;

pub use assertion::Assertion;
pub use certificate::Certificate;
pub use claim::Claim;
use nom::bytes::complete::take;
use nom::number::complete::{u16 as nom_u16, u8 as nom_u8};
use nom::IResult;
pub use proof::{MerkleTreeProofSHA256, Proof, ProofType};
use sha2::{Digest, Sha256};
use std::fmt::{Debug, Formatter};
pub use subject::{Subject, TLSSubjectInfo};
pub use tai_store::{MemoryTaiRootStore, TaiRootStore};
pub use trust_anchor_identifier::{Issuer, TrustAnchorIdentifier};

pub(super) trait Decode<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self>
    where
        Self: Sized;
}

pub trait Encode {
    fn encode(&self) -> Vec<u8>;
}

trait Hashable {
    fn hash(&self) -> Hash
    where
        Self: Encode,
    {
        Hash::Sha256(SHA256(
            Sha256::digest(self.encode()).as_slice().try_into().unwrap(),
        ))
    }
}

trait ListSize {
    const SIZE_LEN: ListLength;
}

enum ListLength {
    U8,
    U16,
}

pub(crate) trait HashSize {
    const HASH_SIZE: usize;
}

impl<'a, T> Decode<'a> for Vec<T>
where
    T: Decode<'a> + Sized + ListSize,
{
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = match T::SIZE_LEN {
            ListLength::U8 => {
                let (bytes, length) = nom_u8(input)?;
                (bytes, length as usize)
            }
            ListLength::U16 => {
                let (bytes, length) = nom_u16(nom::number::Endianness::Big)(input)?;
                (bytes, length as usize)
            }
        };
        let mut vec = Vec::new();
        let mut vec_bytes = &bytes[0..length];
        while !vec_bytes.is_empty() {
            let item;
            (vec_bytes, item) = T::decode(vec_bytes)?;
            vec.push(item);
        }
        Ok((&bytes[length..], vec))
    }
}

impl<T> Encode for Vec<T>
where
    T: Encode + ListSize,
{
    fn encode(&self) -> Vec<u8> {
        let mut res = match T::SIZE_LEN {
            // placeholder for size
            ListLength::U8 => {
                vec![0]
            }
            ListLength::U16 => {
                vec![0, 0]
            }
        };

        for item in self {
            res.append(&mut item.encode());
        }
        match T::SIZE_LEN {
            ListLength::U8 => {
                assert!(res.len() - 1 <= u8::MAX as usize);
                let len = ((res.len() - 1) as u8).to_be_bytes();
                res[0..1].copy_from_slice(&len);
            }
            ListLength::U16 => {
                assert!(res.len() - 2 <= u16::MAX as usize);
                let len = ((res.len() - 2) as u16).to_be_bytes();
                res[0..2].copy_from_slice(&len);
            }
        }

        res
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SHA256(pub(crate) [u8; 32]);

// TODO this might no be universally applicable.
//  Maybe create a new type instead, which implements ListSize
impl ListSize for SHA256 {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl HashSize for SHA256 {
    const HASH_SIZE: usize = 32;
}

impl SHA256 {
    fn to_hex(&self) -> String {
        self.0
            .iter()
            .fold(String::with_capacity(self.0.len() * 2), |s, byte| {
                format!("{s}{byte:x?}")
            })
    }
}

impl<'a> Decode<'a> for SHA256 {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, sha) = take(32usize)(input)?;
        // TODO remove `expect()`
        Ok((
            bytes,
            Self(sha.try_into().expect("sha256 did expect more data")),
        ))
    }
}

impl Encode for SHA256 {
    fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl Debug for SHA256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

#[non_exhaustive]
#[derive(Eq, PartialEq)]
pub enum Hash {
    Sha256(SHA256),
}

impl Hash {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Hash::Sha256(sha) => sha.0.as_slice(),
        }
    }
}

impl From<[u8; 32]> for SHA256 {
    fn from(value: [u8; 32]) -> Self {
        SHA256(value)
    }
}

impl Debug for Hash {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Hash::Sha256(hash) => {
                write!(f, "sha256:{}", hash.to_hex())
            }
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
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
    Unknown(u16),
}

impl<'a> Decode<'a> for SignatureScheme {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, code) = nom_u16(nom::number::Endianness::Big)(input)?;
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
            _ => Self::Unknown(code),
        };
        Ok((bytes, sig))
    }
}

impl Encode for SignatureScheme {
    fn encode(&self) -> Vec<u8> {
        match self {
            SignatureScheme::RSA_PKCS1_SHA1 => vec![0x02, 0x01],
            SignatureScheme::ECDSA_SHA1_Legacy => vec![0x02, 0x03],
            SignatureScheme::RSA_PKCS1_SHA256 => vec![0x04, 0x01],
            SignatureScheme::ECDSA_NISTP256_SHA256 => vec![0x04, 0x03],
            SignatureScheme::RSA_PKCS1_SHA384 => vec![0x05, 0x01],
            SignatureScheme::ECDSA_NISTP384_SHA384 => vec![0x05, 0x03],
            SignatureScheme::RSA_PKCS1_SHA512 => vec![0x06, 0x01],
            SignatureScheme::ECDSA_NISTP521_SHA512 => vec![0x06, 0x03],
            SignatureScheme::RSA_PSS_SHA256 => vec![0x08, 0x04],
            SignatureScheme::RSA_PSS_SHA384 => vec![0x08, 0x05],
            SignatureScheme::RSA_PSS_SHA512 => vec![0x08, 0x06],
            SignatureScheme::ED25519 => vec![0x08, 0x07],
            SignatureScheme::ED448 => vec![0x08, 0x08],
            SignatureScheme::Unknown(_) => unimplemented!(),
        }
    }
}

#[derive(Clone)]
pub enum PayloadU16<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl<'a> PayloadU16<'a> {
    pub fn into_owned(self) -> PayloadU16<'static> {
        match self {
            Self::Borrowed(p) => PayloadU16::Owned(p.to_vec()),
            Self::Owned(p) => PayloadU16::Owned(p),
        }
    }

    pub fn bytes(&'a self) -> &'a [u8] {
        match self {
            PayloadU16::Borrowed(p) => p,
            PayloadU16::Owned(p) => p.as_slice(),
        }
    }

    pub fn len(&self) -> u16 {
        debug_assert!(self.bytes().len() < u16::MAX as usize);
        self.bytes().len() as u16
    }

    pub fn is_empty(&self) -> bool {
        self.bytes().is_empty()
    }
}

impl<'a> Decode<'a> for PayloadU16<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = nom_u16(nom::number::Endianness::Big)(input)?;
        let (bytes, payload) = take(length)(bytes)?;
        Ok((bytes, PayloadU16::Borrowed(payload)))
    }
}

impl Encode for PayloadU16<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut res = self.len().to_be_bytes().to_vec();
        res.extend_from_slice(self.bytes());
        res
    }
}

impl Debug for PayloadU16<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.bytes())
    }
}

#[derive(Clone)]
pub struct PayloadU8(pub Vec<u8>);

impl<'a> Decode<'a> for PayloadU8 {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = nom_u8(input)?;
        let (bytes, payload) = take(length)(bytes)?;
        Ok((bytes, PayloadU8(payload.to_vec())))
    }
}

impl Encode for PayloadU8 {
    fn encode(&self) -> Vec<u8> {
        debug_assert!(self.0.len() < u8::MAX as usize);
        let mut res = (self.0.len() as u8).to_be_bytes().to_vec();
        res.extend_from_slice(&self.0);
        res
    }
}

impl Debug for PayloadU8 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x?}", self.0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::tai_store::test::TestStore;

    #[test]
    fn basic() {
        let test_store = TestStore {};

        let bytes = include_bytes!("../../assets/my-cert-tai");
        Certificate::decode(bytes, &test_store).unwrap();

        let bytes = include_bytes!("../../assets/my-cert-big-tai");
        Certificate::decode(bytes, &test_store).unwrap();
    }
}

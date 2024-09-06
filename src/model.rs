use core::net::{Ipv4Addr, Ipv6Addr};
use der_parser::Oid;
use log::warn;
use nom::bytes::complete::take;
use nom::error::Error;
use nom::number::complete::{u16, u64, u8};
use nom::IResult;
use std::fmt::{Debug, Formatter};

trait Decode<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self>
    where
        Self: Sized;
}

#[derive(Debug)]
pub struct Certificate<'a> {
    assertion: Assertion<'a>,
    proof: Proof<'a>,
}

impl<'a> Certificate<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, assertion) = AssertionBinary::decode(input)?;
        let (bytes, proof) = ProofBinary::decode(bytes)?;
        Ok((
            bytes,
            Self {
                assertion: assertion.try_into()?,
                proof: proof.try_into()?,
            },
        ))
    }
}

#[derive(Debug)]
pub enum Subject<'a> {
    Tls(TLSSubjectInfo<'a>),
    Unknown,
}

#[derive(Debug)]
pub struct Assertion<'a> {
    subject: Subject<'a>,
    claims: Vec<Claim<'a>>,
}

impl<'a> TryFrom<AssertionBinary<'a>> for Assertion<'a> {
    type Error = nom::Err<Error<&'a [u8]>>;

    fn try_from(assertion: AssertionBinary<'a>) -> Result<Self, Self::Error> {
        let subject = match assertion.subject_type {
            SubjectType::Tls => {
                let (bytes, info) = TLSSubjectInfo::decode(assertion.subject_info.0)?;
                assert!(bytes.is_empty());
                Subject::Tls(info)
            }
            SubjectType::Unknown => Subject::Unknown,
        };
        Ok(Self {
            subject,
            claims: assertion
                .claims
                .into_iter()
                .map(Claim::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[derive(Debug)]
struct AssertionBinary<'a> {
    subject_type: SubjectType,
    subject_info: PayloadU16<'a>,
    claims: Vec<ClaimBinary<'a>>,
}

impl<'a> AssertionBinary<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, subject_type) = SubjectType::decode(input)?;
        let (bytes, subject_info) = PayloadU16::decode(bytes)?;
        let (bytes, claims) = Vec::decode(bytes)?;
        Ok((
            bytes,
            Self {
                subject_type,
                subject_info,
                claims,
            },
        ))
    }
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

#[derive(Debug)]
struct ProofBinary<'a> {
    #[cfg(feature = "v02")]
    trust_anchor: TrustAnchor<'a>,
    #[cfg(feature = "v03")]
    trust_anchor: TrustAnchorIdentifier<'a>,
    proof_data: PayloadU16<'a>,
}

impl<'a> ProofBinary<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, trust_anchor) = TrustAnchor::decode(input)?;
        let (bytes, proof_data) = PayloadU16::decode(bytes)?;
        Ok((
            bytes,
            Self {
                trust_anchor,
                proof_data,
            },
        ))
    }
}

#[derive(Debug)]
struct Proof<'a> {
    #[cfg(feature = "v02")]
    trust_anchor: TrustAnchor<'a>,
    #[cfg(feature = "v03")]
    trust_anchor: TrustAnchorIdentifier<'a>,
    proof_data: ProofData<'a>,
}

impl<'a> TryFrom<ProofBinary<'a>> for Proof<'a> {
    type Error = nom::Err<Error<&'a [u8]>>;
    fn try_from(proof: ProofBinary<'a>) -> Result<Self, Self::Error> {
        match proof.trust_anchor.proof_type {
            ProofType::MerkleTreeSha256 => {
                let (bytes, tree) = MerkleTreeProofSHA256::decode(proof.proof_data.0)?;
                assert!(bytes.is_empty());
                Ok(Self {
                    trust_anchor: proof.trust_anchor,
                    proof_data: ProofData::MerkleTreeSha256(tree),
                })
            }
            ProofType::Unknown => {
                warn!("Unknown proof {:?}", proof);
                Ok(Self {
                    trust_anchor: proof.trust_anchor,
                    proof_data: ProofData::Unknown,
                })
            }
        }
    }
}

#[derive(Debug)]
pub enum ProofData<'a> {
    MerkleTreeSha256(MerkleTreeProofSHA256<'a>),
    Unknown,
}

/// RFC draft-beck-tls-trust-anchor-ids-01
#[derive(Debug)]
pub struct TrustAnchor<'a> {
    proof_type: ProofType,
    data: PayloadU8<'a>,
}

impl<'a> TrustAnchor<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, proof_type) = ProofType::decode(input)?;
        let (bytes, data) = PayloadU8::decode(bytes)?;
        Ok((bytes, Self { proof_type, data }))
    }
}

impl TrustAnchor<'_> {
    fn proof_type(&self) -> ProofType {
        self.proof_type
    }
}

#[derive(Debug)]
pub struct TrustAnchorIdentifier<'a>(Oid<'a>);

impl<'a> Decode<'a> for TrustAnchorIdentifier<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, oid) = Oid::from_der_relative(input).expect("unhandled OID error");
        Ok((bytes, Self(oid)))
    }
}

impl TrustAnchorIdentifier<'_> {
    fn proof_type(&self) -> ProofType {
        ProofType::MerkleTreeSha256 // TODO make this dependent on the actual trust anchor
    }
}

#[derive(Debug)]
pub struct MerkleTreeProofSHA256<'a> {
    index: u64,
    path: Vec<HashValueSHA256<'a>>,
}

impl<'a> Decode<'a> for MerkleTreeProofSHA256<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, index) = u64(nom::number::Endianness::Big)(input)?;
        let (bytes, path) = Vec::decode(bytes)?;
        Ok((bytes, MerkleTreeProofSHA256 { index, path }))
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

#[derive(Debug)]
pub struct ClaimBinary<'a> {
    claim_type: ClaimType,
    claim_info: PayloadU16<'a>,
}

#[derive(Debug)]
pub enum Claim<'a> {
    Dns(Vec<DNSName<'a>>),
    DnsWildcard(Vec<DNSName<'a>>),
    IPv4(Vec<Ipv4Addr>),
    IPv6(Vec<Ipv6Addr>),
    Unknown,
}

impl<'a> TryFrom<ClaimBinary<'a>> for Claim<'a> {
    type Error = nom::Err<Error<&'a [u8]>>;

    fn try_from(claim: ClaimBinary<'a>) -> Result<Self, Self::Error> {
        match claim.claim_type {
            ClaimType::Dns => {
                let (rem_bytes, result) = Vec::decode(claim.claim_info.0)?;
                assert!(rem_bytes.is_empty());
                Ok(Claim::Dns(result))
            }
            ClaimType::DnsWildcard => {
                let (rem_bytes, result) = Vec::decode(claim.claim_info.0)?;
                assert!(rem_bytes.is_empty());
                Ok(Claim::DnsWildcard(result))
            }
            ClaimType::Ipv4 => {
                let (rem_bytes, result) = Vec::decode(claim.claim_info.0)?;
                assert!(rem_bytes.is_empty());
                Ok(Claim::IPv4(result))
            }
            ClaimType::Ipv6 => {
                let (rem_bytes, result) = Vec::decode(claim.claim_info.0)?;
                assert!(rem_bytes.is_empty());
                Ok(Claim::IPv6(result))
            }
            ClaimType::Unknown => {
                warn!("Unknown claim type");
                Ok(Claim::Unknown)
            }
        }
    }
}

pub struct DNSName<'a>(pub &'a [u8]);

impl Debug for DNSName<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSName({})", std::str::from_utf8(self.0).unwrap())
    }
}

impl<'a> Decode<'a> for DNSName<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        // FIXME Here the Go implementation seems to diverge from the RFC
        // let (bytes, length) = u8(input)?;
        let (bytes, length) = u16(nom::number::Endianness::Big)(input)?;
        assert_ne!(length, 0, "A DNS name must not be of length 0");
        let (bytes, name) = take(length)(bytes)?;
        assert!(name.is_ascii(), "DNS name must be valid ASCII");
        // TODO check if lowercase
        // TODO proper error handling (no except() or assert!())
        Ok((bytes, Self(name)))
    }
}

impl<'a> Decode<'a> for Ipv4Addr {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, a) = take(4usize)(input)?;
        Ok((bytes, Self::new(a[0], a[1], a[2], a[3])))
    }
}

impl<'a> Decode<'a> for Ipv6Addr {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, a) = take(16usize)(input)?;
        // TODO find a nicer way to do that
        Ok((
            bytes,
            Self::from(TryInto::<[u8; 16]>::try_into(&a[0..16]).expect("16 octets")),
        ))
    }
}

impl<'a> Decode<'a> for ClaimBinary<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, claim_type) = ClaimType::decode(input)?;
        let (bytes, claim_info) = PayloadU16::decode(bytes)?;
        Ok((
            bytes,
            Self {
                claim_type,
                claim_info,
            },
        ))
    }
}

#[derive(Debug)]
pub enum ClaimType {
    Dns,
    DnsWildcard,
    Ipv4,
    Ipv6,
    Unknown,
}

impl ClaimType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::Dns,
            1 => Self::DnsWildcard,
            2 => Self::Ipv4,
            3 => Self::Ipv6,
            _ => Self::Unknown,
        };
        Ok((bytes, claim))
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ProofType {
    MerkleTreeSha256,
    Unknown,
}

impl ProofType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::MerkleTreeSha256,
            _ => Self::Unknown,
        };
        Ok((bytes, claim))
    }
}

#[derive(Debug)]
pub enum SubjectType {
    Tls,
    Unknown,
}

impl SubjectType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::Tls,
            _ => Self::Unknown,
        };
        Ok((bytes, claim))
    }
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
        let bytes = include_bytes!("../assets/cert-two-assertions");
        dbg!(Certificate::decode(bytes).unwrap());

        let bytes = include_bytes!("../assets/cert-single-assertion");
        dbg!(Certificate::decode(bytes).unwrap());
    }
}

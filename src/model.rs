use nom::bytes::complete::take;
use nom::error::{Error, ErrorKind};
use nom::number::complete::{u16, u8};
use nom::IResult;

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
        let (bytes, assertion) = Assertion::decode(input)?;
        let (bytes, proof) = Proof::decode(bytes)?;
        Ok((bytes, Self { assertion, proof }))
    }
}

#[derive(Debug)]
pub struct Assertion<'a> {
    subject_type: SubjectType,
    subject_info: PayloadU16<'a>,
    claims: Vec<Claim<'a>>,
}

impl<'a> Assertion<'a> {
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
pub struct Proof<'a> {
    trust_anchor: TrustAnchor<'a>,
    proof_data: PayloadU16<'a>,
}

impl<'a> Proof<'a> {
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

#[derive(Debug)]
pub struct Claim<'a> {
    claim_type: ClaimType,
    claim_info: PayloadU16<'a>,
}

impl<'a> Decode<'a> for Claim<'a> {
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
}

impl ClaimType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::Dns,
            1 => Self::DnsWildcard,
            2 => Self::Ipv4,
            3 => Self::Ipv6,
            // TODO check if this is a meaningful error
            _ => Err(nom::Err::Failure(Error::new(bytes, ErrorKind::Digit)))?,
        };
        Ok((bytes, claim))
    }
}

#[derive(Debug)]
pub enum ProofType {
    MerkleTreeSha256,
}

impl ProofType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::MerkleTreeSha256,
            // TODO check if this is a meaningful error
            _ => Err(nom::Err::Failure(Error::new(bytes, ErrorKind::Digit)))?,
        };
        Ok((bytes, claim))
    }
}

#[derive(Debug)]
pub enum SubjectType {
    Tls,
}

impl SubjectType {
    fn decode(input: &[u8]) -> IResult<&[u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let claim = match value {
            0 => Self::Tls,
            // TODO check if this is a meaningful error
            _ => Err(nom::Err::Failure(Error::new(bytes, ErrorKind::Digit)))?,
        };
        Ok((bytes, claim))
    }
}

#[derive(Debug)]
pub struct PayloadU16<'a>(pub &'a [u8]);

impl<'a> PayloadU16<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = u16(nom::number::Endianness::Big)(input)?;
        let (bytes, payload) = take(length)(bytes)?;
        Ok((bytes, PayloadU16(payload)))
    }
}

#[derive(Debug)]
pub struct PayloadU8<'a>(pub &'a [u8]);

impl<'a> PayloadU8<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, length) = u8(input)?;
        let (bytes, payload) = take(length)(bytes)?;
        Ok((bytes, PayloadU8(payload)))
    }
}


#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn basic(){
        let bytes = include_bytes!("../assets/cert-two-assertions");
        Certificate::decode(bytes).unwrap();
        
        let bytes = include_bytes!("../assets/cert-single-assertion");
        Certificate::decode(bytes).unwrap();
    }
}
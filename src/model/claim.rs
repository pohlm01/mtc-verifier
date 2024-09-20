use crate::model::{Decode, Encode, ListLength, ListSize, PayloadU16};
use crate::PayloadU8;
use log::warn;
use nom::bytes::complete::take;
use nom::error::Error;
use nom::number::complete::u16;
use nom::IResult;
use std::fmt::{Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub(super) struct ClaimBinary<'a> {
    claim_type: ClaimType,
    claim_info: PayloadU16<'a>,
}

impl ListSize for ClaimBinary<'_> {
    const SIZE_LEN: ListLength = ListLength::U16;
}

#[derive(Debug, Clone)]
pub enum Claim<'a> {
    Dns(Vec<DNSName<'a>>),
    DnsWildcard(Vec<DNSName<'a>>),
    IPv4(Vec<Ipv4Addr>),
    IPv6(Vec<Ipv6Addr>),
    Unknown,
}

impl ListSize for Claim<'_> {
    const SIZE_LEN: ListLength = ListLength::U16;
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

impl Encode for Claim<'_> {
    fn encode(&self) -> Vec<u8> {
        let (t, i) = match self {
            Claim::Dns(c) => (ClaimType::Dns, c.encode()),
            Claim::DnsWildcard(c) => (ClaimType::DnsWildcard, c.encode()),
            Claim::IPv4(c) => (ClaimType::Ipv4, c.encode()),
            Claim::IPv6(c) => (ClaimType::Ipv6, c.encode()),
            Claim::Unknown => {
                // TODO
                unimplemented!()
            }
        };
        ClaimBinary {
            claim_type: t,
            claim_info: PayloadU16(&i),
        }
        .encode()
    }
}

#[derive(Clone)]
pub struct DNSName<'a>(pub &'a [u8]);

impl ListSize for DNSName<'_> {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl Debug for DNSName<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DNSName({})", std::str::from_utf8(self.0).unwrap())
    }
}

impl<'a> Decode<'a> for DNSName<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, PayloadU8(name)) = PayloadU8::decode(input)?;
        assert_ne!(name.len(), 0, "A DNS name must not be of length 0");
        assert!(name.is_ascii(), "DNS name must be valid ASCII");
        // TODO check if lowercase
        // TODO proper error handling (no except() or assert!())
        Ok((bytes, Self(name)))
    }
}

impl Encode for DNSName<'_> {
    fn encode(&self) -> Vec<u8> {
        PayloadU8(self.0).encode()
    }
}

impl<'a> Decode<'a> for Ipv4Addr {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, a) = take(4usize)(input)?;
        Ok((bytes, Self::new(a[0], a[1], a[2], a[3])))
    }
}

impl ListSize for Ipv4Addr {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl Encode for Ipv4Addr {
    fn encode(&self) -> Vec<u8> {
        self.octets().to_vec()
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

impl ListSize for Ipv6Addr {
    const SIZE_LEN: ListLength = ListLength::U16;
}

impl Encode for Ipv6Addr {
    fn encode(&self) -> Vec<u8> {
        self.octets().to_vec()
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

impl Encode for ClaimBinary<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut res = self.claim_type.encode();
        res.extend(self.claim_info.encode());
        res
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

impl Decode<'_> for ClaimType {
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

impl Encode for ClaimType {
    fn encode(&self) -> Vec<u8> {
        match self {
            Self::Dns => vec![0, 0],
            Self::DnsWildcard => vec![0, 1],
            Self::Ipv4 => vec![0, 2],
            Self::Ipv6 => vec![0, 3],
            Self::Unknown => {
                unimplemented!()
            }
        }
    }
}

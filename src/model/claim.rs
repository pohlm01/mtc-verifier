use crate::model::{Decode, PayloadU16};
use log::warn;
use nom::bytes::complete::take;
use nom::error::Error;
use nom::number::complete::{u16, u8};
use nom::IResult;
use std::fmt::{Debug, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub(super) struct ClaimBinary<'a> {
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
        let (bytes, length) = u8(input)?;
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

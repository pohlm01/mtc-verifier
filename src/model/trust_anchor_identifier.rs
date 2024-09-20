use crate::model::{Decode, Encode};
use nom::bytes::complete::take;
use nom::IResult;
use std::fmt::{Debug, Display, Formatter};
use std::num::ParseIntError;
use std::ops::{Deref, Sub};
use std::str::FromStr;

#[derive(Eq, PartialEq, Hash, Clone)]
struct Oid(Vec<u8>);
#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Issuer(Oid);
#[derive(Clone, Copy, Debug)]
pub struct BatchNumber(u32);

impl Sub<usize> for BatchNumber {
    type Output = usize;

    fn sub(self, rhs: usize) -> Self::Output {
        self.0 as usize - rhs
    }
}

impl Encode for Issuer {
    fn encode(&self) -> Vec<u8> {
        self.0 .0.to_vec()
    }
}

impl Deref for BatchNumber {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct TrustAnchorIdentifier {
    pub issuer: Issuer,
    pub batch_number: BatchNumber,
}

impl Decode<'_> for TrustAnchorIdentifier {
    fn decode(input: &'_ [u8]) -> IResult<&'_ [u8], Self> {
        let (bytes, oid) = Oid::decode(input)?;
        let mut segments = oid.segments();
        Ok((
            bytes,
            Self {
                batch_number: BatchNumber(segments.remove(segments.len() - 1)),
                issuer: Issuer(segments.into()),
            },
        ))
    }
}

impl Encode for TrustAnchorIdentifier {
    fn encode(&self) -> Vec<u8> {
        let mut segements = self.issuer.0.segments();
        segements.push(self.batch_number.0);
        let oid: Oid = segements.into();
        let length = oid.0.len();
        assert!(length <= std::u8::MAX as usize);
        let mut result = Vec::with_capacity(length + 1);
        result.push(length as u8);
        result.extend_from_slice(&oid.0);
        result
    }
}

impl Decode<'_> for Oid {
    fn decode(input: &'_ [u8]) -> IResult<&'_ [u8], Self> {
        // TODO check if OID is valid
        let (bytes, oid_length) = nom::number::complete::u8(input)?;
        let (bytes, oid_binary) = take(oid_length)(bytes)?;
        Ok((bytes, Self(oid_binary.to_vec())))
    }
}

impl Oid {
    fn segments(&self) -> Vec<u32> {
        let mut result = Vec::new();
        let mut current_node = 0u32;
        for byte in &self.0 {
            current_node = current_node << 7 | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                // first bit set to 0 → last byte for this node
                result.push(current_node);
                current_node = 0;
            }
        }
        result
    }
}

impl<T: IntoIterator<Item = u32>> From<T> for Oid {
    fn from(segments: T) -> Self {
        let mut res = Vec::new();
        for segment in segments {
            for j in (0..4).rev() {
                let cur = (segment >> (j * 7)) as u8;
                if cur != 0 || j == 0 {
                    let mut byte: u8 = cur & 0x7F;
                    if j != 0 {
                        byte |= 0x80;
                    }
                    res.push(byte);
                }
            }
        }
        Self(res)
    }
}

impl Display for Oid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        for segment in self.segments() {
            if !first {
                write!(f, ".")?;
            }
            first = false;
            write!(f, "{}", segment)?;
        }
        Ok(())
    }
}

impl FromStr for Oid {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.split('.')
            .map(|s| s.parse::<u32>())
            .collect::<Result<Vec<u32>, _>>()?
            .into())
    }
}

impl FromStr for Issuer {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl Display for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for Oid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl Debug for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

use crate::model::proof::ProofType;
use crate::model::Decode;
use nom::bytes::complete::take;
use nom::number::complete::u8;
use nom::IResult;
use std::fmt::{Debug, Display, Formatter};

pub struct TrustAnchorIdentifier<'a>(&'a [u8]);

impl<'a> Decode<'a> for TrustAnchorIdentifier<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        // TODO check if OID is valid
        let (bytes, oid_length) = u8(input)?;
        let (bytes, oid_binary) = take(oid_length)(bytes)?;
        Ok((bytes, Self(oid_binary)))
    }
}

impl Display for TrustAnchorIdentifier<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        let mut current_node = 0u32;
        for byte in self.0 {
            current_node = current_node << 7 | (byte & 0x7F) as u32;
            if byte & 0x80 == 0 {
                // first bit set to 0 → last byte for this node
                if !first {
                    write!(f, ".")?;
                } else {
                    first = false;
                }
                write!(f, "{}", current_node)?;
                current_node = 0;
            }
        }
        Ok(())
    }
}

impl Debug for TrustAnchorIdentifier<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl TrustAnchorIdentifier<'_> {
    pub fn proof_type(&self) -> ProofType {
        ProofType::MerkleTreeSha256 // TODO make this dependent on the actual trust anchor
    }
}

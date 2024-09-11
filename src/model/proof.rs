use crate::model::trust_anchor_identifier::TrustAnchorIdentifier;
use crate::model::{Decode, HashValueSHA256, PayloadU16};
use log::warn;
use nom::error::Error;
use nom::number::complete::u64;
use nom::IResult;

#[derive(Debug)]
pub(super) struct ProofBinary<'a> {
    trust_anchor: TrustAnchorIdentifier<'a>,
    proof_data: PayloadU16<'a>,
}

impl<'a> Decode<'a> for ProofBinary<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, trust_anchor) = TrustAnchorIdentifier::decode(input)?;
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
pub struct Proof<'a> {
    trust_anchor: TrustAnchorIdentifier<'a>,
    proof_data: ProofData<'a>,
}

impl<'a> TryFrom<ProofBinary<'a>> for Proof<'a> {
    type Error = nom::Err<Error<&'a [u8]>>;
    fn try_from(proof: ProofBinary<'a>) -> Result<Self, Self::Error> {
        match proof.trust_anchor.proof_type() {
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

#[derive(Debug, Copy, Clone)]
pub enum ProofType {
    MerkleTreeSha256,
    Unknown,
}

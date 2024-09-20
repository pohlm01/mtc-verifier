use crate::model::trust_anchor_identifier::TrustAnchorIdentifier;
use crate::model::{Decode, PayloadU16, SHA256};
use crate::TaiRootStore;
use log::warn;
use nom::number::complete::u64;
use nom::IResult;

#[derive(Debug)]
pub(super) struct ProofBinary<'a> {
    trust_anchor: TrustAnchorIdentifier,
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

#[derive(Debug, Clone)]
pub struct Proof<'a> {
    pub(crate) trust_anchor: TrustAnchorIdentifier,
    pub(crate) proof_data: ProofData<'a>,
}

impl<'a> Proof<'a> {
    pub(super) fn try_from(
        proof: ProofBinary<'a>,
        root_store: &dyn TaiRootStore,
    ) -> IResult<&'a [u8], Self> {
        match root_store.proof_type(&proof.trust_anchor) {
            Some(ProofType::MerkleTreeSha256) => {
                let (bytes, tree) = MerkleTreeProofSHA256::decode(proof.proof_data.0)?;
                Ok((
                    bytes,
                    Self {
                        trust_anchor: proof.trust_anchor,
                        proof_data: ProofData::MerkleTreeSha256(tree),
                    },
                ))
            }
            _ => {
                warn!("Unknown proof {:?}", proof);
                Ok((
                    &[],
                    Self {
                        trust_anchor: proof.trust_anchor,
                        proof_data: ProofData::Unknown(proof.proof_data.0),
                    },
                ))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProofData<'a> {
    MerkleTreeSha256(MerkleTreeProofSHA256<'a>),
    Unknown(&'a [u8]),
}

#[derive(Debug, Clone)]
pub struct MerkleTreeProofSHA256<'a> {
    pub(crate) index: u64,
    pub(crate) path: Vec<SHA256<'a>>,
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

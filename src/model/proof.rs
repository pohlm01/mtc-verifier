use crate::model::trust_anchor_identifier::TrustAnchorIdentifier;
use crate::model::{Decode, Encode, PayloadU16, SHA256};
use crate::TaiRootStore;
use log::warn;
use nom::number::complete::{u16, u64};
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
        proof: &'a ProofBinary<'a>,
        root_store: &dyn TaiRootStore,
    ) -> IResult<&'a [u8], Self> {
        match root_store.proof_type(&proof.trust_anchor) {
            Some(ProofType::MerkleTreeSha256) => {
                let (bytes, tree) = MerkleTreeProofSHA256::decode(proof.proof_data.bytes())?;
                Ok((
                    bytes,
                    Self {
                        trust_anchor: proof.trust_anchor.clone(),
                        proof_data: ProofData::MerkleTreeSha256(tree),
                    },
                ))
            }
            _ => {
                warn!("Unknown proof {:?}", proof);
                Ok((
                    &[],
                    Self {
                        trust_anchor: proof.trust_anchor.clone(),
                        proof_data: ProofData::Unknown(proof.proof_data.clone()),
                    },
                ))
            }
        }
    }
}

impl Proof<'_> {
    pub fn into_owned(self) -> Proof<'static> {
        Proof {
            trust_anchor: self.trust_anchor,
            proof_data: self.proof_data.into_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ProofData<'a> {
    MerkleTreeSha256(MerkleTreeProofSHA256),
    Unknown(PayloadU16<'a>),
}

impl ProofData<'_> {
    pub fn into_owned(self) -> ProofData<'static> {
        match self {
            Self::MerkleTreeSha256(s) => ProofData::MerkleTreeSha256(s),
            Self::Unknown(u) => ProofData::Unknown(u.into_owned()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MerkleTreeProofSHA256 {
    pub(crate) index: u64,
    pub(crate) path: Vec<SHA256>,
}

impl<'a> Decode<'a> for MerkleTreeProofSHA256 {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, index) = u64(nom::number::Endianness::Big)(input)?;
        let (bytes, path) = Vec::decode(bytes)?;
        Ok((bytes, MerkleTreeProofSHA256 { index, path }))
    }
}

impl Encode for MerkleTreeProofSHA256 {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = self.index.to_be_bytes().to_vec();
        bytes.append(&mut self.path.encode());
        bytes
    }
}

#[derive(Debug, Copy, Clone)]
pub enum ProofType {
    MerkleTreeSha256,
    Unknown,
}

impl Encode for Proof<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut proof_data = match &self.proof_data {
            ProofData::MerkleTreeSha256(data) => data.encode(),
            ProofData::Unknown(data) => data.encode(),
        };
        let mut bytes = self.trust_anchor.encode();
        bytes.append(&mut proof_data);
        bytes
    }
}

impl<'a> Decode<'a> for ProofType {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, value) = u16(nom::number::Endianness::Big)(input)?;
        let proof_type = match value {
            0 => ProofType::MerkleTreeSha256,
            _ => ProofType::Unknown,
        };
        Ok((bytes, proof_type))
    }
}

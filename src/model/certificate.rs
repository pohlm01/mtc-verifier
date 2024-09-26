use crate::model::assertion::AssertionBinary;
use crate::model::proof::{Proof, ProofBinary, ProofData};
use crate::model::tree::{HashAssertionInput, HashNodeInput};
use crate::model::{Assertion, Decode, Encode, Hashable};
use crate::{Error, Hash, TaiRootStore};
use nom::IResult;

#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub(crate) assertion: Assertion<'a>,
    pub(crate) proof: Proof<'a>,
}

impl<'a> Certificate<'a> {
    pub fn decode(input: &'a [u8], root_store: &dyn TaiRootStore) -> IResult<&'a [u8], Self> {
        let (bytes, assertion) = AssertionBinary::decode(input)?;
        let (bytes, proof) = ProofBinary::decode(bytes)?;
        assert!(bytes.is_empty());
        let (bytes, proof) = Proof::try_from(proof, root_store)?;
        assert!(bytes.is_empty());
        Ok((
            bytes,
            Self {
                assertion: assertion.try_into()?,
                proof,
            },
        ))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.assertion.encode();
        bytes.append(&mut self.proof.encode());
        bytes
    }

    pub fn recompute_root_hash(&self) -> Result<Hash<'static>, Error> {
        let batch_id = &self.proof.trust_anchor;
        let proof = match &self.proof.proof_data {
            ProofData::MerkleTreeSha256(p) => p,
            ProofData::Unknown(_) => Err(Error::UnknownCA)?,
        };
        let mut hash = HashAssertionInput {
            batch_id,
            index: proof.index,
            abridged_assertion: self.assertion.clone().into(),
        }
        .hash();

        let mut remaining = proof.index;

        for (i, v) in proof.path.iter().enumerate() {
            if remaining & 1 == 1 {
                hash = HashNodeInput {
                    batch_id,
                    left: Hash::Sha256(v.to_owned()),
                    right: hash,
                    level: (i + 1) as u8,
                    index: remaining >> 1,
                }
                .hash();
            } else {
                hash = HashNodeInput {
                    batch_id,
                    left: hash,
                    right: Hash::Sha256(v.to_owned()),
                    level: (i + 1) as u8,
                    index: remaining >> 1,
                }
                .hash();
            }
            remaining >>= 1;
        }
        assert_eq!(remaining, 0);

        Ok(hash)
    }
}

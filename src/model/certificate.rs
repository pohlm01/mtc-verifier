use crate::model::assertion::AssertionBinary;
use crate::model::proof::{Proof, ProofBinary, ProofData};
// use crate::model::tai_store::test::TestStore;
use crate::model::tree::{HashAssertionInput, HashNodeInput};
use crate::model::{Assertion, Decode, Encode, Hashable};
use crate::{Error, Hash, SignatureScheme, Subject, TaiRootStore};
use log::warn;

#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    pub(crate) assertion: Assertion<'a>,
    pub(crate) proof: Proof<'a>,
}

impl Certificate<'_> {
    pub fn decode<'a>(
        input: &'a [u8],
        root_store: &dyn TaiRootStore,
    ) -> Result<Certificate<'static>, nom::Err<nom::error::Error<&'a [u8]>>> {
        let (bytes, assertion) = AssertionBinary::decode(input)?;
        let (bytes, proof) = ProofBinary::decode(bytes)?;
        assert!(bytes.is_empty());
        let (bytes, proof) = Proof::try_from(&proof, root_store).unwrap();
        assert!(bytes.is_empty());
        Ok(Certificate {
            assertion: TryInto::<Assertion>::try_into(&assertion)
                .unwrap()
                .into_owned(),
            proof: proof.into_owned(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.assertion.encode();
        bytes.append(&mut self.proof.encode());
        bytes
    }

    pub fn recompute_root_hash(&self) -> Result<Hash, Error> {
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

    pub fn signature_scheme(&self) -> Option<SignatureScheme> {
        match &self.assertion.subject {
            Subject::Tls(tls) => Some(tls.signature),
            Subject::Unknown(_) => None,
        }
    }

    pub fn public_key(&self) -> Option<&[u8]> {
        match &self.assertion.subject {
            Subject::Tls(tls) => Some(tls.public_key.bytes()),
            Subject::Unknown(_) => {
                warn!("Could not read public key from unknown subject type");
                None
            }
        }
    }
}

impl Certificate<'_> {
    pub fn trust_anchor_identifier(&self) -> String {
        self.proof.trust_anchor.to_string()
    }
}

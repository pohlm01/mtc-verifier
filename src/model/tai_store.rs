use crate::model::proof::ProofType;
use crate::model::trust_anchor_identifier::Issuer;
use crate::{Hash, TrustAnchorIdentifier, SHA256};
use log::trace;
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::Entry;
use std::fmt::Debug;

pub trait TaiRootStore: Debug {
    fn proof_type(&self, tai: &TrustAnchorIdentifier) -> Option<ProofType>;
    fn root_hash(&self, tai: &TrustAnchorIdentifier) -> Option<&Hash>;
    fn supported_tais(&self) -> Vec<TrustAnchorIdentifier>;
}

#[derive(Debug)]
struct CAParams {
    proof_type: ProofType,

    first_batch_number: usize,
    root_hashes: VecDeque<Hash>,
}

#[derive(Default, Debug)]
pub struct MemoryTaiRootStore {
    ca_params: HashMap<Issuer, CAParams>,
}

#[derive(Debug)]
pub enum Error {
    WrongHashLength,
    CANotFound,
}

impl TaiRootStore for MemoryTaiRootStore {
    fn proof_type(&self, tai: &TrustAnchorIdentifier) -> Option<ProofType> {
        self.ca_params.get(&tai.issuer).map(|p| p.proof_type)
    }

    fn root_hash(&self, batch_id: &TrustAnchorIdentifier) -> Option<&Hash> {
        let params = self.ca_params.get(&batch_id.issuer)?;
        let hash = params
            .root_hashes
            .get(batch_id.batch_number - params.first_batch_number);
        trace!(
            "resolved root_hash for batch_id {:?} as {:?}",
            batch_id,
            hash
        );
        hash
    }

    fn supported_tais(&self) -> Vec<TrustAnchorIdentifier> {
        todo!()
    }
}

impl MemoryTaiRootStore {
    pub fn add(&mut self, issuer: Issuer, proof_type: ProofType) {
        let params = CAParams {
            proof_type,
            first_batch_number: 0,
            root_hashes: VecDeque::new(),
        };
        self.ca_params.insert(issuer, params);
    }

    /// Appends the hash as the root of the next batch
    pub fn add_root_hash(&mut self, issuer: Issuer, root_hash: Vec<u8>) -> Result<(), Error> {
        match self.ca_params.entry(issuer) {
            Entry::Occupied(mut entry) => {
                let ca = entry.get_mut();
                let hash = match ca.proof_type {
                    ProofType::MerkleTreeSha256 => Hash::Sha256(SHA256(root_hash.try_into().unwrap())),
                    ProofType::Unknown => {
                        unimplemented!()
                    }
                };
                let hash_str = format!("{hash:?}");
                ca.root_hashes.push_back(hash);
                trace!(
                    "added {:?} as root hash for batch {} of CA {}",
                    hash_str,
                    ca.first_batch_number + ca.root_hashes.len() - 1,
                    entry.key()
                );
            }
            Entry::Vacant(_) => Err(Error::CANotFound)?,
        };
        Ok(())
    }

    /// Removes the hash of the oldest batch stored
    pub fn remove_root_hash(&mut self, issuer: Issuer) {
        self.ca_params.entry(issuer).and_modify(|ca| {
            if ca.root_hashes.pop_front().is_some() {
                ca.first_batch_number += 1;
            }
        });
    }

    /// Reports for which batch numbers the store knows root hashes.
    /// Returns a tuple `(min, max)`, both inclusive
    pub fn known_batch_numbers(&self, issuer: &Issuer) -> Option<(u32, u32)> {
        let ca = self.ca_params.get(issuer)?;
        Some((
            ca.first_batch_number as u32,
            (ca.first_batch_number + ca.root_hashes.len() - 1) as u32,
        ))
    }
}

#[cfg(test)]
pub mod test {
    use crate::model::proof::ProofType;
    use crate::{Hash, TaiRootStore, TrustAnchorIdentifier};

    #[derive(Debug)]
    pub struct TestStore {}

    impl TaiRootStore for TestStore {
        fn proof_type(&self, _tai: &TrustAnchorIdentifier) -> Option<ProofType> {
            Some(ProofType::MerkleTreeSha256)
        }

        fn root_hash(&self, _tai: &TrustAnchorIdentifier) -> Option<&Hash> {
            unimplemented!()
        }

        fn supported_tais(&self) -> Vec<TrustAnchorIdentifier> {
            todo!()
        }
    }
}

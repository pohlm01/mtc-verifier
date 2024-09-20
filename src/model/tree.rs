use crate::model::subject::SubjectType;
use crate::model::{Encode, Hashable};
use crate::Hash::Sha256;
use crate::{Assertion, Claim, Hash, Subject, TrustAnchorIdentifier, SHA256};

pub(crate) struct HashAssertionInput<'a> {
    // u8 distinguisher: 2
    pub(crate) batch_id: &'a TrustAnchorIdentifier,
    pub(crate) index: u64,
    pub(crate) abridged_assertion: AbridgedAssertion<'a>,
}

pub(crate) struct AbridgedAssertion<'a> {
    pub(crate) subject_type: SubjectType,
    pub(crate) subject_info_hash: Hash<'a>,
    pub(crate) claims: Vec<Claim<'a>>,
}

pub(crate) struct HashNodeInput<'a> {
    // u8 distinguisher: 1
    pub(crate) batch_id: &'a TrustAnchorIdentifier,
    pub(crate) index: u64,
    pub(crate) level: u8,
    pub(crate) left: Hash<'a>,
    pub(crate) right: Hash<'a>,
}

pub(crate) struct HashEmptyInput {
    // u8 distinguisher: 0
    pub(crate) batch_id: TrustAnchorIdentifier,
    pub(crate) index: u64,
    pub(crate) level: u8,
}

impl Encode for HashAssertionInput<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut res = vec![2];
        res.extend_from_slice(&self.batch_id.encode());
        res.extend_from_slice(&self.index.to_be_bytes());
        res.extend_from_slice(&self.abridged_assertion.encode());
        res
    }
}

impl Hashable for HashAssertionInput<'_> {}

impl Encode for AbridgedAssertion<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut res = self.subject_type.encode();
        res.extend_from_slice(self.subject_info_hash.bytes());
        res.extend_from_slice(&self.claims.encode());

        res
    }
}
impl Hashable for AbridgedAssertion<'_> {}

impl Encode for HashNodeInput<'_> {
    fn encode(&self) -> Vec<u8> {
        let mut res = vec![1];
        res.extend_from_slice(&self.batch_id.encode());
        res.extend_from_slice(&self.index.to_be_bytes());
        res.extend_from_slice(&self.level.to_be_bytes());
        res.extend_from_slice(self.left.bytes());
        res.extend_from_slice(self.right.bytes());
        res
    }
}
impl Hashable for HashNodeInput<'_> {}

impl Encode for HashEmptyInput {
    fn encode(&self) -> Vec<u8> {
        let mut res = vec![0];
        res.extend_from_slice(&self.batch_id.encode());
        res.extend_from_slice(&self.index.to_be_bytes());
        res.extend_from_slice(&self.level.to_be_bytes());
        res
    }
}
impl Hashable for HashEmptyInput {}

impl<'a> From<Assertion<'a>> for AbridgedAssertion<'a> {
    fn from(a: Assertion<'a>) -> Self {
        let (subject_type, hash) = match &a.subject {
            Subject::Tls(info) => (SubjectType::Tls, info.hash::<sha2::Sha256>()),
            Subject::Unknown => {
                unimplemented!()
            }
        };
        Self {
            subject_type,
            subject_info_hash: Sha256(SHA256::Owned(hash.as_slice().try_into().unwrap())),
            claims: a.claims,
        }
    }
}

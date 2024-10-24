use crate::model::subject::SubjectType;
use crate::model::{Encode, HashSize, Hashable};
use crate::Hash::Sha256;
use crate::{
    Assertion, Claim, Hash, PayloadU16, SignatureScheme, Subject, TrustAnchorIdentifier, SHA256,
};
use sha2::Digest;

pub(crate) struct HashAssertionInput<'a> {
    // u8 distinguisher: 2
    pub(crate) batch_id: &'a TrustAnchorIdentifier,
    pub(crate) index: u64,
    pub(crate) abridged_assertion: AbridgedAssertion<'a>,
}

pub(crate) struct AbridgedAssertion<'a> {
    pub(crate) subject_type: SubjectType,
    pub(crate) abridged_subject_info: PayloadU16<'a>,
    pub(crate) claims: Vec<Claim>,
}

pub(crate) struct AbridgedTLSSubjectInfo {
    pub(crate) signature_scheme: SignatureScheme,
    pub(crate) public_key_hash: Hash,
}

pub(crate) struct HashNodeInput<'a> {
    // u8 distinguisher: 1
    pub(crate) batch_id: &'a TrustAnchorIdentifier,
    pub(crate) index: u64,
    pub(crate) level: u8,
    pub(crate) left: Hash,
    pub(crate) right: Hash,
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
        res.extend_from_slice(&self.abridged_subject_info.encode());
        res.extend_from_slice(&self.claims.encode());

        res
    }
}
impl Hashable for AbridgedAssertion<'_> {}

impl Encode for AbridgedTLSSubjectInfo {
    fn encode(&self) -> Vec<u8> {
        let mut res = self.signature_scheme.encode();
        res.extend_from_slice(self.public_key_hash.bytes());
        res
    }
}
impl Hashable for AbridgedTLSSubjectInfo {}

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

impl<'a> From<Assertion<'a>> for AbridgedAssertion<'a> {
    fn from(a: Assertion<'a>) -> Self {
        let (subject_type, abridged_info) = match &a.subject {
            Subject::Tls(info) => (
                SubjectType::Tls,
                AbridgedTLSSubjectInfo {
                    signature_scheme: info.signature,
                    public_key_hash: Sha256(
                        TryInto::<[u8; SHA256::HASH_SIZE]>::try_into(
                            sha2::Sha256::digest(info.public_key.bytes()).as_slice(),
                        )
                        .unwrap()
                        .into(),
                    ),
                },
            ),
            Subject::Unknown(_) => {
                unimplemented!()
            }
        };
        Self {
            subject_type,
            abridged_subject_info: PayloadU16::Owned(abridged_info.encode()),
            claims: a.claims,
        }
    }
}

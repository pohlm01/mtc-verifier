use crate::model::claim::{Claim, ClaimBinary};
use crate::model::subject::{Subject, SubjectType, TLSSubjectInfo};
use crate::model::{Decode, Encode, PayloadU16};
use nom::error::Error;
use nom::IResult;

#[derive(Debug, Clone)]
pub struct Assertion<'a> {
    pub(crate) subject: Subject<'a>,
    pub(super) claims: Vec<Claim>,
}

impl<'a> TryFrom<&'a AssertionBinary<'a>> for Assertion<'a> {
    type Error = nom::Err<Error<&'a [u8]>>;

    fn try_from(assertion: &'a AssertionBinary<'a>) -> Result<Self, Self::Error> {
        let subject = match assertion.subject_type {
            SubjectType::Tls => {
                let (bytes, info) = TLSSubjectInfo::decode(assertion.subject_info.bytes())?;
                assert!(bytes.is_empty());
                Subject::Tls(info)
            }
            SubjectType::Unknown => Subject::Unknown(assertion.subject_info.clone()),
        };
        Ok(Self {
            subject,
            claims: assertion
                .claims
                .iter()
                .map(Claim::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl Assertion<'_> {
    pub fn into_owned(self) -> Assertion<'static> {
        Assertion {
            subject: self.subject.into_owned(),
            claims: self.claims,
        }
    }
}

#[derive(Debug)]
pub(super) struct AssertionBinary<'a> {
    subject_type: SubjectType,
    subject_info: PayloadU16<'a>,
    claims: Vec<ClaimBinary<'a>>,
}

impl<'a> Decode<'a> for AssertionBinary<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, subject_type) = SubjectType::decode(input)?;
        let (bytes, subject_info) = PayloadU16::decode(bytes)?;
        let (bytes, claims) = Vec::decode(bytes)?;
        Ok((
            bytes,
            Self {
                subject_type,
                subject_info,
                claims,
            },
        ))
    }
}

impl Encode for Assertion<'_> {
    fn encode(&self) -> Vec<u8> {
        let (subject_type, mut subject_info) = match &self.subject {
            Subject::Tls(info) => (
                SubjectType::Tls,
                PayloadU16::Borrowed(&info.encode()).encode(),
            ),
            Subject::Unknown(bytes) => (SubjectType::Unknown, bytes.encode()),
        };
        let mut bytes = subject_type.encode();
        bytes.append(&mut subject_info);
        bytes.append(&mut self.claims.encode());
        bytes
    }
}

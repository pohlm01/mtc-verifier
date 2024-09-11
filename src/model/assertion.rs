use crate::model::claim::{Claim, ClaimBinary};
use crate::model::subject::{Subject, SubjectType, TLSSubjectInfo};
use crate::model::{Decode, PayloadU16};
use nom::error::Error;
use nom::IResult;

#[derive(Debug)]
pub struct Assertion<'a> {
    subject: Subject<'a>,
    claims: Vec<Claim<'a>>,
}

impl<'a> TryFrom<AssertionBinary<'a>> for Assertion<'a> {
    type Error = nom::Err<Error<&'a [u8]>>;

    fn try_from(assertion: AssertionBinary<'a>) -> Result<Self, Self::Error> {
        let subject = match assertion.subject_type {
            SubjectType::Tls => {
                let (bytes, info) = TLSSubjectInfo::decode(assertion.subject_info.0)?;
                assert!(bytes.is_empty());
                Subject::Tls(info)
            }
            SubjectType::Unknown => Subject::Unknown,
        };
        Ok(Self {
            subject,
            claims: assertion
                .claims
                .into_iter()
                .map(Claim::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
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

use crate::model::assertion::AssertionBinary;
use crate::model::proof::{Proof, ProofBinary};
use crate::model::{Assertion, Decode};
use nom::IResult;

#[derive(Debug)]
pub struct Certificate<'a> {
    assertion: Assertion<'a>,
    proof: Proof<'a>,
}

impl<'a> Decode<'a> for Certificate<'a> {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, assertion) = AssertionBinary::decode(input)?;
        let (bytes, proof) = ProofBinary::decode(bytes)?;
        Ok((
            bytes,
            Self {
                assertion: assertion.try_into()?,
                proof: proof.try_into()?,
            },
        ))
    }
}

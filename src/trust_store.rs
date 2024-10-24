use crate::model::trust_anchor_identifier::BatchNumber;
use crate::model::{Decode, HashSize};
use crate::{
    Hash, Issuer, PayloadU16, ProofType, TLSSubjectInfo, TaiRootStore, TrustAnchorIdentifier,
    SHA256,
};
use log::warn;
use nom::bytes::complete::take;
use nom::IResult;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug)]
struct CAParams {
    issuer: Issuer,
    public_key: TLSSubjectInfo<'static>,
    proof_type: ProofType,
    start_time: u64,
    batch_duration: u64,
    lifetime: u64,
    validity_window_size: u32,
    storage_window_size: u64,
    http_server: String,
}

impl<'a> Decode<'a> for CAParams {
    fn decode(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (bytes, issuer) = Issuer::decode(input)?;
        let (bytes, public_key) = TLSSubjectInfo::decode(bytes)?;
        let (bytes, proof_type) = ProofType::decode(bytes)?;
        let (bytes, start_time) = nom::number::complete::u64(nom::number::Endianness::Big)(bytes)?;
        let (bytes, batch_duration) =
            nom::number::complete::u64(nom::number::Endianness::Big)(bytes)?;
        let (bytes, lifetime) = nom::number::complete::u64(nom::number::Endianness::Big)(bytes)?;
        let (bytes, validity_window_size) =
            nom::number::complete::u32(nom::number::Endianness::Big)(bytes)?;
        let (bytes, storage_window_size) =
            nom::number::complete::u64(nom::number::Endianness::Big)(bytes)?;
        let (bytes, http_server) = PayloadU16::decode(bytes)?;

        Ok((
            bytes,
            Self {
                issuer,
                public_key: public_key.into_owned(),
                proof_type,
                start_time,
                batch_duration,
                lifetime,
                validity_window_size,
                storage_window_size,
                http_server: String::from_utf8_lossy(http_server.bytes()).to_string(),
            },
        ))
    }
}

#[derive(Debug)]
struct ValidityWindow<T> {
    batch_number: u32,
    tree_heads: Vec<T>,
}

impl<'a, H> ValidityWindow<H>
where
    H: HashSize + Decode<'a>,
{
    fn decode(input: &'a [u8], num_tree_heads: usize) -> IResult<&'a [u8], Self> {
        let (bytes, batch_number) =
            nom::number::complete::u32(nom::number::Endianness::Big)(input)?;
        let (bytes, tree_heads) = take(num_tree_heads * H::HASH_SIZE)(bytes)?;

        Ok((
            bytes,
            Self {
                batch_number,
                tree_heads: tree_heads
                    .chunks_exact(H::HASH_SIZE)
                    .map(H::decode)
                    .collect::<Result<Vec<(&[u8], H)>, nom::Err<nom::error::Error<&[u8]>>>>()?
                    .into_iter()
                    .map(|(_, hash)| hash)
                    .collect(),
            },
        ))
    }
}

#[derive(Debug)]
pub struct OsMtcRootStore {
    cas: HashMap<Issuer, CAParams>,
    trust_roots: HashMap<TrustAnchorIdentifier, Hash>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Decode,
    Something,
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl<T> From<nom::Err<T>> for Error {
    fn from(_: nom::Err<T>) -> Self {
        Error::Decode
    }
}

impl OsMtcRootStore {
    pub fn from_disk(path: impl AsRef<Path>) -> Result<Self, Error> {
        let ca_directories = fs::read_dir(path)
            .inspect_err(|err| {
                warn!("MTC directory not found: {:?}", err);
            })?
            .collect::<Vec<_>>();

        let mut res = Self {
            cas: Default::default(),
            trust_roots: Default::default(),
        };
        for ca_dir in ca_directories.into_iter().flatten() {
            if let Ok(metadata) = ca_dir.metadata() {
                if metadata.is_dir() {
                    let (ca_params, roots) = read_single_ca_dir(&ca_dir.path())?;

                    let mut batch_num =
                        roots.batch_number as i64 - ca_params.validity_window_size as i64 + 1;
                    for root in roots.tree_heads {
                        if batch_num >= 0 {
                            res.trust_roots.insert(
                                TrustAnchorIdentifier {
                                    issuer: ca_params.issuer.clone(),
                                    batch_number: BatchNumber(batch_num as u32),
                                },
                                match ca_params.proof_type {
                                    ProofType::MerkleTreeSha256 => Hash::Sha256(root),
                                    ProofType::Unknown => {
                                        unimplemented!()
                                    }
                                },
                            );
                        }
                        batch_num += 1;
                    }

                    res.cas.insert(ca_params.issuer.clone(), ca_params);
                } else {
                    continue;
                }
            }
        }
        Ok(dbg!(res))
    }
}

// TODO @max get rid of the hardcoded SHA256 in the signature
fn read_single_ca_dir(path: &Path) -> Result<(CAParams, ValidityWindow<SHA256>), Error> {
    let mut params_path = PathBuf::from(path);
    params_path.push("ca-params");
    let mut f = File::open(params_path)?;
    let mut param_bytes = vec![];
    f.read_to_end(&mut param_bytes)?;
    let (_, params) = CAParams::decode(&param_bytes)?;

    let mut validity_window_path = PathBuf::from(path);
    validity_window_path.push("validity-window");
    let mut f = File::open(validity_window_path)?;
    let mut param_bytes = vec![];
    f.read_to_end(&mut param_bytes)?;
    let (_, validity_window) =
        ValidityWindow::decode(&param_bytes, params.validity_window_size as usize)?;
    dbg!(&validity_window);

    Ok((params, validity_window))
}

impl TaiRootStore for OsMtcRootStore {
    fn proof_type(&self, tai: &TrustAnchorIdentifier) -> Option<ProofType> {
        Some(self.cas.get(&tai.issuer)?.proof_type)
    }

    fn root_hash(&self, tai: &TrustAnchorIdentifier) -> Option<&Hash> {
        self.trust_roots.get(tai)
    }

    fn supported_tais(&self) -> Vec<TrustAnchorIdentifier> {
        self.trust_roots.keys().cloned().collect()
    }
}

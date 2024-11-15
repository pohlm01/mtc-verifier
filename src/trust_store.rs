use crate::model::trust_anchor_identifier::BatchNumber;
use crate::model::{Decode, HashSize};
use crate::{
    Encode, Hash, Issuer, PayloadU16, ProofType, SignatureScheme, TLSSubjectInfo, TaiRootStore,
    TrustAnchorIdentifier, SHA256,
};
use log::{trace, warn};
use nom::bytes::complete::take;
use nom::IResult;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::DetachedSignature;
use pqcrypto_traits::sign::PublicKey;
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub(crate) struct CAParams {
    pub(crate) issuer: Issuer,
    pub(crate) public_key: TLSSubjectInfo<'static>,
    pub(crate) proof_type: ProofType,
    pub(crate) start_time: u64,
    pub(crate) batch_duration: u64,
    pub(crate) lifetime: u64,
    pub(crate) validity_window_size: u32,
    pub(crate) storage_window_size: u64,
    pub(crate) http_server: String,
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

#[derive(Debug)]
struct LabeledValidityWindow<T> {
    issuer: Issuer,
    validity_window: ValidityWindow<T>,
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
    Something(&'static str),
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

                    res.cas
                        .insert(ca_params.issuer.clone(), ca_params);
                } else {
                    continue;
                }
            }
        }
        Ok(res)
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

    let mut signature_path = PathBuf::from(path);
    signature_path.push("signature");
    let mut f = File::open(signature_path)?;
    let mut signature_bytes = vec![];
    f.read_to_end(&mut signature_bytes)?;

    let mut validity_window_path = PathBuf::from(path);
    validity_window_path.push("validity-window");
    let mut f = File::open(validity_window_path)?;
    let mut validity_window_bytes = vec![];
    f.read_to_end(&mut validity_window_bytes)?;

    verify_ca_signature(&params, &validity_window_bytes, &signature_bytes)?;

    let (_, validity_window) =
        ValidityWindow::decode(&validity_window_bytes, params.validity_window_size as usize)?;

    Ok((params, validity_window))
}

fn verify_ca_signature(
    params: &CAParams,
    validity_window: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let public_key = if matches!(params.public_key.signature, SignatureScheme::MlDsa87) {
        PublicKey::from_bytes(params.public_key.public_key.bytes()).unwrap()
    } else {
        Err(Error::Something(
            "cannot read CA public key as key the algorithm is not supported",
        ))?
    };

    let mut labeled_validity_window = Vec::from(b"Merkle Tree Crts ValidityWindow\0");
    labeled_validity_window.append(&mut params.issuer.encode());
    labeled_validity_window.extend_from_slice(validity_window);

    mldsa87::verify_detached_signature(
        &DetachedSignature::from_bytes(signature).unwrap(),
        &labeled_validity_window,
        &public_key,
    )
    .map_err(|err| {
        dbg!(err);
        Error::Something("could not verify signature")
    })?;
    trace!("Successfully verified CA signature");
    Ok(())
}

impl TaiRootStore for OsMtcRootStore {
    fn proof_type(&self, tai: &TrustAnchorIdentifier) -> Option<ProofType> {
        Some(self.cas.get(&tai.issuer)?.proof_type)
    }

    fn root_hash(&self, tai: &TrustAnchorIdentifier) -> Option<&Hash> {
        self.trust_roots.get(tai)
    }

    fn ca_params(&self, issuer: &Issuer) -> Option<&CAParams> {
        self.cas.get(issuer)
    }

    fn supported_tais(&self) -> Vec<TrustAnchorIdentifier> {
        self.trust_roots
            .keys()
            .cloned()
            .collect()
    }
}

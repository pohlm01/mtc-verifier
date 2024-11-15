mod model;
mod trust_store;

pub use model::*;
use rustls_pki_types::UnixTime;
pub use trust_store::*;

#[derive(Debug)]
pub enum Error {
    Truncated,
    ExtraBytes,
    UnknownCA,
    RootHashMismatch,
    InvalidSignature,
    BadCertificate,
    Expired,
}

pub fn verify_cert(cert: &[u8], now: UnixTime, root_store: &dyn TaiRootStore) -> Result<(), Error> {
    let cert = Certificate::decode(cert, root_store).unwrap();
    let root_hash = root_store
        .root_hash(&cert.proof.trust_anchor)
        .ok_or(Error::UnknownCA)?;

    let ca_params = root_store
        .ca_params(&cert.proof.trust_anchor.issuer)
        .ok_or(Error::UnknownCA)?;
    if is_expired(ca_params, &cert, now) {
        return Err(Error::Expired);
    }

    let recomputed_hash = cert.recompute_root_hash()?;
    if dbg!(root_hash) == dbg!(&recomputed_hash) {
        return Ok(());
    }

    Err(Error::BadCertificate)
}

fn is_expired(ca_params: &CAParams, cert: &Certificate, now: UnixTime) -> bool {
    let issue_time =
        ca_params.start_time + cert.proof.trust_anchor.batch_number * ca_params.batch_duration;
    issue_time + ca_params.lifetime < now.as_secs()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MemoryTaiRootStore, ProofType};
    use std::num::ParseIntError;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    #[test]
    fn valid_cert() {
        env_logger::init();

        let mut root_store = MemoryTaiRootStore::default();
        root_store.add("62253.12.15".parse().unwrap(), ProofType::MerkleTreeSha256);
        root_store
            .add_root_hash(
                "62253.12.15".parse().unwrap(),
                decode_hex("a7b081f10c7116c30781a957c3f52625c4d831c8d61ceea021db101ab3c901cf")
                    .unwrap(),
            )
            .unwrap();
        root_store
            .add_root_hash(
                "62253.12.15".parse().unwrap(),
                decode_hex("ec54c78c4353af4f337edd66d3527b6fcc15a6281f5ff45701e290dd9ba53f18")
                    .unwrap(),
            )
            .unwrap();

        let bytes = include_bytes!("../assets/my-cert");
        verify_cert(
            bytes,
            UnixTime::since_unix_epoch(SystemTime::now().duration_since(UNIX_EPOCH).unwrap()),
            &root_store,
        )
        .unwrap();
    }
}

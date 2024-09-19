# Merkle Tree Certificate Verifier

Implementation of the IETF draft [Merkle Tree Certificates for TLS](https://datatracker.ietf.org/doc/html/draft-davidben-tls-merkle-tree-certs-03)
which proposes a new certificate type for TLS.
Merkle Tree Certificates are designed to avoid big Post-Quantum
(PQ) signatures where possible while still being safe[^1] against an advisory with a powerful quantum computer.

[^1]: Merkle Tree Certificates focus on the security of the certificate but not on the encryption of the TLS traffic.

This project aims for compatibility with the CA implementation of [bwesterb/mtc](https://github.com/bwesterb/mtc).
It will be used by (a fork of) [rustls](https://github.com/rustls/rustls) to explore the practicality of the IETF draft.
This is part of my Master's thesis.

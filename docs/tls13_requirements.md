# TLS 1.3 Requirements

This file contains the list of cryptographic primitives needed to implement all suites in TLS 1.3.

## Requirements

- [ ] ECDHE:
  - [ ] Parameters: [P-256, P-384, P-521](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
  - [ ] Parameters: [Curve25519, Curve448](https://datatracker.ietf.org/doc/html/rfc7748)
- [ ] DHE:
  - [ ] Parameters: [ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192](https://datatracker.ietf.org/doc/html/rfc7919)
- [ ] RSA: [DOI pp. 120-126](https://dl.acm.org/doi/pdf/10.1145/359340.359342)
- [ ] ECDSA
- [ ] EdDSA: [RFC](https://datatracker.ietf.org/doc/html/rfc8032)

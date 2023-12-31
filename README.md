# Crypto-go

Package containing implementations of cryptographic functions.

## Functions

Hashing:

- [x] MD2 ([code](src/hash/md2/md2.go), [RFC1319](https://www.rfc-editor.org/info/rfc1319))
- [ ] MD4
- [ ] MD5
- [ ] Whirlpool
- [ ] Tiger/192
- [ ] RIPEMD-160
- [ ] SHA0 (FIPS 180)
- [x] SHA-1 ([FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final))
- [x] SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256) ([code (224/256)](src/hash/sha256/sha256.go), [code (384/512/512_224/512_256)](src/hash/sha512/sha512.go), [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final))
- [ ] SHA3 (SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, SHAKE256)
- [ ] HMAC

Stream ciphers:

- [ ] Salsa20/12, Salsa20/20
- [ ] ChaCha12, ChaCha20 (Done ChaCha20)
- [ ] CSS stream cipher
- [ ] RC4

Block ciphers:

- [x] DES ([code](src/cipher/des/des.go), [FIPS 46-3](https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25))
- [x] 3-DES ([code](src/cipher/des/des.go), [FIPS 46-3](https://csrc.nist.gov/publications/detail/fips/46/3/archive/1999-10-25))
- [ ] AES (AES128)
- [ ] DESX

MAC:

- [ ] CRC32
- [ ] ECBC
- [ ] ANSI CBC-MAC (ANSI X9.9, ANSI X9.19, ISO 8731-1, ISO/IEC 9797)
- [ ] CMAC
- [ ] NMAC
- [ ] PMAC
- [ ] XECB

Modes of operations:

- [x] ECB ([code](src/cipher/modes/ecb.go), [FIPS 81](https://csrc.nist.gov/publications/detail/fips/81/archive/1980-12-02))
- [ ] CBC ([FIPS 81](https://csrc.nist.gov/publications/detail/fips/81/archive/1980-12-02))
- [ ] CFB ([FIPS 81](https://csrc.nist.gov/publications/detail/fips/81/archive/1980-12-02))
- [ ] OFB ([FIPS 81](https://csrc.nist.gov/publications/detail/fips/81/archive/1980-12-02))
- [ ] CTR ([NIST SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final))
- [ ] OCB
- [ ] IAPM
- [ ] XCBC
- [ ] CCFB
- [ ] GCM

Signatures:

- [ ] RSA_PKCS1
- [ ] ECDSA (SECP256R1, SECP384R1, SECP512R1)
- [ ] RSASSA-PSS (pk rsaEncryption, pk RSASSA-PSS)
- [ ] EdDSA (ed25519, ed448)
- [ ] DSA

Certificates:

- [ ] X509, OpenPGP

EC groups:

- [ ] ECDHE (SECP256R1, SECP384R1, SECP512R1, X25519, X448)
- [ ] DHE (FFDHE 2048, 3072, 4096, 6144, 8192)

Key derivation:

- [ ] HKDP (RFC 5869)

To sort:

- [ ] POLY1305

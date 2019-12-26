# openssl-engine-kms

OpenSSL engine implementation that provides support for utilizing AWS
KMS asymmetric keys for signing, verification, encryption and
decryption, and optionally for random generation.

## Description

## Installation

Build library by running:

```
$ cargo build --release
```

Building requires minimum Rust version 1.37.0.

Either specify `$(PWD)/target/release/libopenssl_engine_kms.so`
directly as the engine name, or copy it under `OPENSSL_ENGINES`
directory (such as `/usr/lib/x86_64-linux-gnu/engines-1.1/`) as
`kms.so` and use `kms` as engine name.

## Usage

Basic usage from OpenSSL command line:

**Load key**:

```
$ openssl pkey -engine kms -inform engine \
    -in arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -pubout -text
engine "kms" set.
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk8SMcv6qVmTvqCOm+W3v4Xr+F0y1
iw/FnLvAGmXh9yCU+kjmKTI8YhNZuppNhUjMVq1kKm9cibyoZZt3FQ8VqA==
-----END PUBLIC KEY-----
Private-Key: (256 bit)
pub:
    04:93:c4:8c:72:fe:aa:56:64:ef:a8:23:a6:f9:6d:
    ef:e1:7a:fe:17:4c:b5:8b:0f:c5:9c:bb:c0:1a:65:
    e1:f7:20:94:fa:48:e6:29:32:3c:62:13:59:ba:9a:
    4d:85:48:cc:56:ad:64:2a:6f:5c:89:bc:a8:65:9b:
    77:15:0f:15:a8
ASN1 OID: prime256v1
NIST CURVE: P-256
```

Notes:
- Reading either a private key or a public key (by using `-pubin`)
  will produce the same result: a public key fetched from KMS, as no
  private key part is ever exportable.
- Both EC and RSA keys are supported, in all bit lengths supported by
  KMS.

**Sign**:

```
$ openssl pkeyutl -engine kms -sign -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in digest.bin -out sig.bin -pkeyopt digest:sha256
engine "kms" set.
```

Notes:
- For RSA keys both PKCS#1 and PSS padding are supported with digests
  SHA-256, SHA-384 and SHA-512. Use `-pkeyopt rsa_padding_mode:pss` if
  you wish to use PSS.
- For EC keys ECDSA is supported with digest SHA-256, SHA-384 and
  SHA-512.
- Digest SHA-1 is not supported by KMS for security reasons. 

**Verify**:

```
$ openssl pkeyutl -engine kms -verify -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in digest.bin -sigfile sig.bin -pkeyopt digest:sha256
engine "kms" set.
Signature Verified Successfully
```

Notes:
- By default, only key is loaded from KMS and verification is
  performed locally for performance and convenience.
- Set environment variable `OPENSSL_ENGINE_KMS_USE_PUBKEY` to a
  non-empty string to enable the use for KMS for the actual verify
  operation.

**Decrypt**:

```
$ openssl pkeyutl -engine kms -decrypt -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in encrypted.bin -out decrypted.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA1
engine "kms" set.
```

Notes:
- Only OAEP is supported with either digest SHA-1 or SHA-256. Use
  `-pkeyopt rsa_padding_mode:oaep` to enable OAEP and
  `-pkey_oaep_md:SHA256` to set the digest.

**Encrypt**:

```
$ openssl pkeyutl -engine kms -encrypt -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in plain.bin -out encrypted.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA1
engine "kms" set.
```

Notes:
- By default, only key is loaded from KMS and encryption is
  performed locally for performance and convenience.
- Set environment variable `OPENSSL_ENGINE_KMS_USE_PUBKEY` to a
  non-empty string to enable the use for KMS for the actual encrypt
  operation.

**Generate random**:

```
$ OPENSSL_ENGINE_KMS_USE_RAND=true openssl rand -engine kms -out rand.bin 128
engine "kms" set.
```

- Random generation by KMS is disabled by default.
- Set environment variable `OPENSSL_ENGINE_KMS_USE_RAND` to a
  non-empty string to enable the use of KMS for random generation.

## License

This library is licensed under [CC0 1.0 Universal](LICENSE)

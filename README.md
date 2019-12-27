# openssl-engine-kms

OpenSSL engine implementation that provides support for utilizing AWS
KMS asymmetric keys for signing, verification, encryption and
decryption, and optionally for utilizing KMS for random generation.

This is useful because it allows the private key parts to not reside
on the computer that is running the program using KMS - indeed, KMS
does not allow the private key to be exported at all. This means that
even in the face of full server compromise, the private key cannot be
stolen, and access to the key can very easily be revoked. AWS KMS also
provides a clear audit log in the form of CloudTrail, which will
record each operation that uses a key, making it very easy to verify
all the users of the key.

Some possible uses for this engine:

- HTTPS server without exposing private key
- Use TLS client certificate authentication without exposing private key
- Create Certificate Signing Requests (CSRs) for a key to be submitted for signing by a CA
- Create self-signed certificate for a key
- Operate a CA without exposing the CA private key
- Sign messages using S/MIME without exposing private key
- Decrypt messages using S/MIME without exposing private key
- Operate a Time Stamping Authority (TSA) without exposting private key

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

There are two things that need to happen for this engine to be useful
in OpenSSL: the engine needs to be loaded, and the private key (or
public key) must be loaded from the engine.

Loading of the engine happens either by directly loading it by calling
`ENGINE_by_id("kms")`, or by loading it from a dynamic library by
calling `ENGINE_by_id("dynamic")` and then by using
`ENGINE_ctrl_cmd_string` to send both `SO_PATH` and `LOAD` commands to
the engine. On the `openssl` command line both of these methods are
automatically used by specifying either `-engine kms` or `-engine
path/to/kms.so`.

Loading the private or public key from the engine happens by calling
`ENGINE_load_private_key` or `ENGINE_load_public_key` on the engine.
The resulting loaded key is equivalent regardless of which method is
used as KMS never exposes the private key directly. The `key_id`
argument is passed directly as key id to the KMS API, which currently
supports Key ID, Key ARN, Alias Name or Alias ARN as possible values.

Software that supports OpenSSL engines such as PKCS#11 or TPM usually
already has functionality to do these operations. For example Node.js
(13.x or later) exposes these via the `privateKeyEngine` and
`privateKeyIdentifier` options on TLS contexts.

Environment variables:

- `OPENSSL_ENGINE_KMS_USE_RAND`: If set to non-empty string, enables
  the use of KMS for all random generation inside OpenSSL. This is
  usually not necessary unless the installation does not have a good
  random source, or if certified high quality randomness is required,
  or if an audit log should be generated from all random generation
  operations.
- `OPENSSL_ENGINE_KMS_USE_PUBKEY`: If set to non-empty string, enables
  the use of KMS (instead of OpenSSL) also for verify and encrypt
  operations. This is usually not necessary as these operations only
  use the public key, but may be desired for audit purposes, or
  ensuring the verification happens inside a FIPS boundary.
- `OPENSSL_ENGINE_KMS_LOG`: If there is a need to obtain more verbose
  logs from the engine, this environment variable may be set to a log
  level. The format is described by
  [env_logger](https://docs.rs/env_logger/0.7.1/env_logger/) Rust
  crate. For example, to enable trace level logging for the engine
  itself, specify `openssl_engine_kms=trace`, or to enable trace
  logging for all packages, specify `trace`.

## Usage from command-line

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

**Generate self-signed certificate**:

```
$ openssl req -new -x509 -days 365 -subj '/CN=my key/' -sha256 -engine kms -keyform engine \
    -key arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -out cert.pem
```

**Run TLS server**:

```
$ openssl s_server -engine kms -keyform engine -cert cert.pem \
    -key arn:aws:kms:eu-west-1:378072147349:key/82a458d8-b594-4702-b55e-4f00588ed070
```

## License

This library is licensed under [CC0 1.0 Universal](LICENSE)

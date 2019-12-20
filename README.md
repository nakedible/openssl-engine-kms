# openssl-engine-kms

OpenSSL engine implementation that provides support for utilizing AWS
KMS asymmetric keys for signing, verification, encryption and
decryption, and optionally for random generation.

## Description

## Installation

## Usage

Basic usage from OpenSSL command line:

**Load key**:

```console
$ openssl pkey -engine kms -inform engine -in arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef -pubout
engine "kms" set.
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk8SMcv6qVmTvqCOm+W3v4Xr+F0y1
iw/FnLvAGmXh9yCU+kjmKTI8YhNZuppNhUjMVq1kKm9cibyoZZt3FQ8VqA==
-----END PUBLIC KEY-----
```

**Sign**:

```console
$ openssl pkeyutl -engine kms -sign -keyform engine -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef -in digest.bin -out sig.bin -pkeyopt digest:sha256
```

**Verify**:

```console
$ openssl pkeyutl -engine kms -verify -keyform engine -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef -in digest.bin -sigfile sig.bin -pkeyopt digest:sha256
Signature Verified Successfully
```

**Encrypt**:

```console
$ openssl pkeyutl -engine kms -encrypt -keyform engine -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef -in plain.bin -out encrypted.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA1
```

**Decrypt**:

```console
$ openssl pkeyutl -engine kms -decrypt -keyform engine -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef -in encrypted.bin -out decrypted.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA1
```

**Generate random**:

```console
$ OPENSSL_ENGINE_KMS_USE_RAND=true openssl rand -engine kms -out rand.bin 128
```

## License

This library is licensed under [CC0 1.0 Universal](LICENSE)

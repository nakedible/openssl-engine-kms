# openssl-engine-kms

OpenSSL engine implementation that provides support for utilizing AWS
KMS asymmetric keys for signing, verification, encryption and
decryption, and optionally for random generation.

## Description

## Installation

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

**Sign**:

```
$ openssl pkeyutl -engine kms -sign -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in digest.bin -out sig.bin -pkeyopt digest:sha256
engine "kms" set.
```

**Verify**:

```
$ openssl pkeyutl -engine kms -verify -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in digest.bin -sigfile sig.bin -pkeyopt digest:sha256
engine "kms" set.
Signature Verified Successfully
```

**Encrypt**:

```
$ openssl pkeyutl -engine kms -encrypt -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in plain.bin -out encrypted.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA1
engine "kms" set.
```

**Decrypt**:

```
$ openssl pkeyutl -engine kms -decrypt -keyform engine \
    -inkey arn:aws:kms:eu-west-1:111122223333:key/deadbeef-dead-dead-dead-deaddeafbeef \
    -in encrypted.bin -out decrypted.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:SHA1
engine "kms" set.
```

**Generate random**:

```
$ OPENSSL_ENGINE_KMS_USE_RAND=true openssl rand -engine kms -out rand.bin 128
engine "kms" set.
```

## License

This library is licensed under [CC0 1.0 Universal](LICENSE)

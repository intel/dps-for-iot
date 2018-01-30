# Message Encryption

The following assumes you are already familiar with the
[DPS message protocol](Message-Protocol.md).

DPS messages are encrypted using
[COSE](https://tools.ietf.org/html/rfc8152).

Keys are provided to DPS via the [keystore].

## Content Encryption

The *protected* section of a DPS message forms the protected
attributes from the application as identified in COSE.  The
*encrypted* section of a DPS message is the plaintext provided to the
content encryption algorithm and is replaced by a COSE object,
either a *COSE_Encrypt_Tagged* or *COSE_Encrypt0_Tagged* object.

The implemented content encryption algorithms are *AES-CCM-16-128-128*
and *AES-CCM-16-64-128*.

## Content Key Distribution

The encryption key is determined by the recipient algorithm.  DPS
supports the *direct*, *A128KW*, *ECDH-ES + HKDF-256*, and *ECDH-ES +
A128KW* recipient algorithms.

The use of the key wrap variants allows multiple recipients to be
included in a message.

### Elliptic Curve Keys

DPS supports the *NIST P-256 (secp256r1)*, *NIST P-384 (secp384r1)*,
and *NIST P-521 (secp521r1)* curves.

Point compression is not supported.  Both the x and y coordinates must
be included in EC key representations such as the ephemeral sender
key.

### Key Derivation Functions

HKDF requires context information to be provided.  This is represented
in COSE as the *COSE_KDF_Context*.

The values of the *identity*, *nonce*, and *other* fields of the
*PartyUInfo* and *PartyVInfo* structures in the *COSE_KDF_Context* are
*nil*.

*SuppPrivInfo* is not included in the *COSE_KDF_Context*.

## Counter Signatures

After encryption, the encrypted content is signed by the sender and
the signature is included as a COSE counter signature.  This allows
intermediate DPS nodes to authenticate the sender of a message without
decrypting the contents of the message.

DPS supports the *ES256*, *ES384*, and *ES512* signature algorithms.

## Examples

An example encrypted publication message, using *AES-CCM-16-128-128*
for the content, *ECDH-ES+A128KW* for the key distribution, and
*ES256* for signing, will look like:

~~~
message = [
  / version / 1,
  / type / 1,
  /unprotected / {
    / port / 1: 42446,
    / ttl / 2: 0
  },
  / protected (aad) / {
    / ttl / 2: 0,
    / pub-id / 3: h'17003AE54085EE56F735764C7631CE61',
    / seq-num / 4: 1,
    / ack-req / 5: false,
    / bloom-filter / 6: [1, 8192, h'002817805F00982A']
  },
  / encrypted (COSE_Encrypt_Tagged) / 96(
    [
      / protected / h'A101181E' / {
          \ alg \ 1: 30 \ AES-CCM-16-128-128 \
        } /,
      / unprotected / {
        / iv / 5: h'0100000017003AE54085EE56F7',
        / countersign / 7: [
          / protected / h'A10126' /
              \ alg \ 1: -7 \ ECDSA 256 \
            } /,
          / unprotected / {
            / kid / 4: h'4450532054657374205075626C6973686572'
          },
          / signature / h'1F14BDB559BB24A50B1C1ECA91938C445CFF64C4A24F075A6105B4679D19AEE439413AD30BE4C6C402031B2B04E7D6C2E4B2BA6A4C788E5C7DDE805654CA38CE'
        ]
      },
      / ciphertext / h'457C20BF6EB818AD98C4D820EFD2B017CACE97C47144E3D6',
      / recipients / [
        [
          / protected / h'A101381C' / {
              \ alg \ 1: -29 \ ECDH-ES+A128KW \
            } /,
          / unprotected / {
            / ephemeral / -1: {
              / kty / 1: 2,
              / crv / -1: 1,
              / x / -2: h'B34D696D855245BB79FCC8F0A328F37B7CC935803DAEC9EBAB97F061A68444E1',
              / y / -3: h'CDF27464CDC3A65DA7EC37139C354940E219A5E55D1A28265A015B2D0A47F72F'
            },
            / kid / 4: h'44505320546573742053756273637269626572'
          },
          / ciphertext / h'CF83EEA4B372FC210A374E44F040EEFA345C569C2D74A322'
        ]
      ]
    ]
  )
]
~~~

[keystore]: @ref keystore "Key Store"

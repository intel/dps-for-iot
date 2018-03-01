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

The implemented content encryption algorithm is *A128GCM*.

## Content Key Distribution
The encryption key is determined by the recipient algorithm.  DPS
supports the *direct*, *A128KW*, and *ECDH-ES + A128KW* recipient
algorithms.

The use of the key wrap variants allows multiple recipients to be
included in a message.

### Elliptic Curve Keys
DPS supports the *NIST P-384 (secp384r1)* and *NIST P-521 (secp521r1)*
curves.

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

DPS supports the *ES384*, and *ES512* signature algorithms.

## Examples

An example encrypted publication message, using *A128GCM* for the
content, *ECDH-ES+A128KW* for the key distribution, and *ES256* for
signing, will look like:

~~~
message = [
  / version / 1,
  / type / 1,
  / unprotected / {
    / port / 1: 41950,
    / ttl / 2: 0
  },
  / protected (aad) / {
    / ttl / 2: 0,
    / pub-id / 3: h'7B2C11676389F49D5DE30507927F3F4F',
    / seq-num / 4: 1,
    / ack-req / 5: false,
    / bloom-filter / 6: [1, 8192, h'00340600CF0C6077']
  },
  / encrypted (COSE_Encrypt_Tagged) / 96(
    [
      / protected / h'A10101' / {
          \ alg \ 1: 1 \ A128GCM \
        } /,
      / unprotected / {
        / iv / 5: h'010000007B2C11676389F49D',
        / countersign / 7: [
          / protected / h'A10126' / {
              \ alg \ 1: -7 \ ECDSA 256 \
            } /,
          / unprotected / {
            / kid / 4: h'4450532054657374205075626C6973686572'
          },
          / signature / h'73EEFD38E07F2EAD476E8D5CF28A86F2A57DC01B2E07E114634A0246132713648BAD1BB380DB8C6101AE45046A1B56E4476439B59A0F4AE50B965827BE376DDF'
        ]
      },
      / ciphertext / h'581C6E4641FDC8970644BAA5305AF84C9D3887F95F808C49',
      / recipients / [
        [
          / protected / h'A101381C' / {
              \ alg \ 1: -29 \ ECDH-ES+A128KW \
            } /,
          / unprotected / {
            / ephemeral / -1: {
              / kty / 1: 2,
              / crv / -1: 1,
              / x / -2: h'7855C03075F337DB8EFD30FD6FD49AFA8852C0B753A5E4E145B023B42FA253F6',
              / y / -3: h'1D4961E5B66068461BB542BAC46F302C750B38C19A4B2A6B46EE79208F800CFA'
            },
            / kid / 4: h'44505320546573742053756273637269626572'
          },
          / ciphertext / h'E45108B6207517C8EC300FA0D69241E814CD8FEF8D396686'
        ]
      ]
    ]
  )
]
~~~

[keystore]: @ref keystore "Key Store"

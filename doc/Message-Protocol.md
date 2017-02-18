# Message Protocol
This section descbribes the DPS message protocol encodings. DPS messages are
encoded in CBOR.

## DPS Message types
DPS has three messages types.
~~~~
message = publication / subscription / ack
~~~~
## Common types
These are types common across the various message types.


### UUID
UUIDs identify publications and are also used as key identifiers for encrypted messages.
~~~~
uuid = bstr .size 16
~~~~
### Bit vector control flags
Bits vectors are usually run-length encoded unless the raw uncencode bit vector
is more compact than the rle-encoded representation. The rle-encoded
flag indicates if the bit vector is encoded or raw.

The rle-complement flags indicates if the complement of the bit vector was
was encoded. The bit vector complement is encoded if this results in a more
compact encoding. This flag is only useful with run-length encoding.
~~~~py
bit-vector-flags = &(
  rle-encoded: 1,
  rle-complement: 2
)
~~~~
###  Bit vector encoding
The bit vector encoding includes control flags, the
bit vector length expressed in bits and the raw
or run-length encoded bit vector data.
~~~~py
bit-vector = [
  flags: uint .bits bit-vector-flags, ; # bit vector control flags
  len: uint,                          ; # bit vector length in bits
  bits: bstr                          ; # raw or rle-encoded bit vector
]
~~~~
### Header field member keys.
For compactness the member keys are encoded as integers as listed below.
~~~~py
header-field = (
  ? 1 => uint,        ; # port number sender is listening on
  ? 2 => bool,        ; # cancel
  ? 3 => int,         ; # ttl - time to live in seconds
  ? 4 => uuid,        ; # pub-id - unique indentifier for a publication
  ? 5 => uint,        ; # seq-num - sequence number for a publication
  ? 6 => bool,        ; # ack-req - indicates if an publisher is requesting an acknowledgement
  ? 7 => bit-vector,  ; # bloom-filter -the bloom filter for a publication
  ? 8 => bool,        ; # inbound-sync - sending subscriber needs to synchronize with receiver
  ? 9 => bool,        ; # outbound-sync - sending subscriber is synchronizing with receiver
  ? 10 => bit-vector, ; # needs - the needs bit vector
  ? 11 => bit-vector  ; # interests - the interests bit vector
)
~~~~
## DPS message types

### Publication message encoding
The encoding of a plaintext publication.
~~~~py
publication = [
  type: 1,
  headers: { * header-field }, ; # port, ttl
  body: { * header-field },    ; # ttl, pub-id, seq-num, ack-req, bloom-filter
  payload: [
    topics: [ + topic: tstr ]
    payload: bstr
  ]
]
~~~~
The encoding of an encrypted publication.
~~~~py
publication = [
  type: 1,
  headers: { * header-field }, ; # port, ttl
  body: { * header-field },    ; # ttl, pub-id, seq-num, ack-req, bloom-filter
  payload: [
    topics: [ + topic: tstr ]
    payload: bstr
  ]
]
~~~~
### Subscription message encoding
Subscription messages are not encrypte so there is only one encoding.
~~~~py
subscription = [
  type: 2,
  headers: { * header-field }, ; # port
  body: { * header-field }     ; # inbound-sync, outbound-sync, needs, interests or empty for unlink
]
~~~~
### Acknowledgement message encoding
The encoding of a plaintext acknowledgement message.
~~~~py
ack = [
  type: 3,
  body: { * header-field },    ; # pub-id, seq-num
  payload: bstr
]
~~~~
The encoding of an encrypted acknowledgement message.
~~~~py
ack = [
  type: 3,
  body: { * header-field },    ; # pub-id, seq-num
  payload: bstr
]
~~~~

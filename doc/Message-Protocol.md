# Message Protocol
This section descbribes the DPS message protocol encodings. DPS
messages are encoded in CBOR.

## Messages
Each message has the same form.

~~~
message = [
  version: 1,
  type: pub / sub / ack / sak,
  unprotected: { * field },
  protected: { * field },
  encrypted: { * field }
]
~~~

### Field member keys
For compactness the member keys are encoded as integers as listed
below.

~~~
field = (
  ? 1 => uint,               ; # port number sender is listening on
  ? 2 => int,                ; # ttl - time to live in seconds
  ? 3 => uuid,               ; # pub-id - unique indentifier for a publication
  ? 4 => uint,               ; # seq-num - sequence number for a publication
  ? 5 => bool,               ; # ack-req - indicates if an publisher is requesting an acknowledgement
  ? 6 => bit-vector,         ; # bloom-filter -the bloom filter for a publication
  ? 7 => sub-flags,          ; # sub-flags - indicates delta or mute
  ? 8 => uuid,               ; # mesh-id - the mesh ID
  ? 9 => bit-vector,         ; # needs - the needs bit vector
  ? 10 => bit-vector,        ; # interests - the interests bit vector
  ? 11 => [ + topic: tstr ], ; # topics - the topic strings
  ? 12 => bstr               ; # data - payload data
)
~~~

The description of each message type includes what fields are
mandatory or optional for each section.

### UUID
UUIDs identify publications and are also used as key identifiers for
encrypted messages.

~~~
uuid = bstr .size 16
~~~

###  Bit vector encoding
The bit vector encoding includes control flags, the bit vector length
expressed in bits and the raw or run-length encoded bit vector data.

~~~
bit-vector = [
  flags: uint .bits bit-vector-flags, ; # bit vector control flags
  len: uint,                          ; # bit vector length in bits
  bits: bstr                          ; # raw or rle-encoded bit vector
]
~~~

### Bit vector control flags
Bits vectors are usually run-length encoded unless the raw unencoded
bit vector is more compact than the rle-encoded representation. The
rle-encoded flag indicates if the bit vector is encoded or raw.

The rle-complement flags indicates if the complement of the bit vector
was was encoded. The bit vector complement is encoded if this results
in a more compact encoding. This flag is only useful with run-length
encoding.

~~~
bit-vector-flags = &(
  rle-encoded: 1,
  rle-complement: 2
)
~~~

### Subscription flags

~~~
sub-flags = &(
  delta: 1,        ; # indicate interests is a delta
  mute: 2          ; # mute has been indicated
)
~~~

## Publication message

~~~
pub = 1
~~~

*port* and *ttl* are mandatory in the *unprotected* section.

*ttl*, *pub-id*, *seq-num*, *ack-req* and *bloom-filter* are
mandatory in the *protected* section.

*topics* and *data* are mandatory in the *encrypted* section.

## Subscription message

~~~
sub = 2
~~~

*port* and *seq-num* are mandatory in the *unprotected* section.

In a regular subscription message, *sub-flags*, *mesh-id*, *needs*
and *interests* are mandatory in the *protected* section.  In an
unlink subscription message those fields shall be absent.

## Acknowledgement message

~~~
ack = 3
~~~

*pub-id* and *seq-num* are mandatory in the *protected* section.

*data* is optional in the *encrypted* section.

## Subscription acknowledgement message

~~~
sak = 4
~~~

*port* and *seq-num* are mandatory in the *unprotected* section.

# Message Protocol

~~~~
message = publication / subscription / ack

uuid = bstr .size 16

bit-vector-flags = &(
  rle-encoded: 1,
  rle-complement: 2
)
bit-vector = [
  flags: uint .bits bit-vector-flags,
  len: uint,
  bits: bstr
]

header-field = (
  ? 1 => uint,        ; port
  ? 2 => bool,        ; cancel
  ? 3 => int,         ; ttl
  ? 4 => uuid,        ; pub-id
  ? 5 => uint,        ; seq-num
  ? 6 => bool,        ; ack-req
  ? 7 => bit-vector,  ; bloom-filter
  ? 8 => bool,        ; inbound-sync
  ? 9 => bool,        ; outbound-sync
  ? 10 => bit-vector, ; needs
  ? 11 => bit-vector  ; interests
)
~~~~

## Publication

~~~~
publication = [
  type: 1,
  headers: { * header-field }, ; port, ttl
  body: { * header-field },    ; ttl, pub-id, seq-num, ack-req, bloom-filter
  payload: [
    topics: [ + topic: tstr ]
    payload: bstr
  ]
]
~~~~

## Subscription

~~~~
subscription = [
  type: 2,
  headers: { * header-field }, ; port
  body: { * header-field }     ; inbound-sync, outbound-sync, needs, interests or empty for unlink
]
~~~~

## Ack

~~~~
ack = [
  type: 3,
  body: { * header-field },    ; pub-id, seq-num
  payload: bstr
]
~~~~

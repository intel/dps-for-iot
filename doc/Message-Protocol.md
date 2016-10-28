# Message Protocol


## Publication

~~~~{.js}
{
  "type": "array",
  "items": [
    { "title": "port", "type": "integer" },
    { "title": "ttl", "type": "integer" },
    { "title": "pubId", "type": "string", "format": "byte" },
    { "title": "sequenceNum", "type": "integer" },
    { "title": "ackRequested", "type": "boolean" },
    { "title": "bf", "type": "$ref/definitions/bitvec" },
    { "title": "topics", "type": "array", "items": { "type": "string" } },
    { "title": "payload", "type": "string", "format": "byte" }
  ],
  "required": [ "port", "ttl", "pubId", "sequenceNum", "ackRequested", "bt", "topics", "payload" ]
}
~~~~

## Subscription

~~~~{.js}
{
  "type": "array",
  "items": [
    { "title": "port", "type": "integer" },
    { "title": "ttl", "type": "integer" },
    { "title": "inboundsync", "type": "boolean" },
    { "title": "outboundsync", "type": "boolean" },
    { "title": "needs", "type": "$ref/definitions/bitvec" },
    { "title": "interests", "type": "$ref/definitions/bitvec" }
  ],
  required: [ "port", "ttl", "inboundsync", "outboundsync", "needs", "interests" ]
}
~~~~

## Ack

~~~~{.js}
{
  "type": "array",
  "items": [
    { "title": "pubId", "type": "string", "format": "byte" },
    { "title": "sequenceNum", "type": "integer" },
    { "title": "payload", "type": "string", "format": "byte" }
  ]
  required: [ "pubId", "sequenceNum", "payload" ]
}
~~~~

## Bitvec

~~~~{.js}
{
  "type": "array",
  "items": [
    { "title": "flags", "type": "integer" },
    { "title": "len", "type": "integer" },
    { "title": "bits", "type": "string", "format": "byte" }
  ],
  "required": [ "flags", "len", "bits" ]
}
~~~~

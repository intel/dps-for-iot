# Message Transports

## Multicast
DPS publication messages may be multicast.  Multicast publications are
wrapped in a CoAP envelope and sent to and received from the default
CoAP port *5683*.

A CoAP wrapped publication message is sent as a non-confirmable PUT
request with options:
- Uri-Path: *dps/pub*
- Content-Format: *application/cbor*

Control over sending and receiving multicast messages is provided via
the *mcastPub* parameter of DPS_StartNode().

## Unicast
All DPS messages may be unicast.  Unicast endpoints may be explicitly
created and destroyed with DPS_Link() and DPS_Unlink().  The port used
in unicast communication is provided via the *listenPort* parameter of
DPS_StartNode().

DPS implements three different transports for sending and receiving
unicast messages.

### UDP
Each DPS message is contained in a single UDP datagram.

### TCP
Each DPS message is prefixed with the length of the message encoded as
a CBOR unsigned integer value.

### DTLS
DTLS provides message authentication, integrity and confidentiality
above UDP.  Each DPS message is contained in a single DTLS datagram.

Key material is provided to the transport via the [keystore].  The
transport makes the following requests:
- The trusted Certificate Authority (CA) chain for peer certificate
  verification via DPS_CAHandler().
- The endpoint's own certificate chain and private key via
  DPS_KeyHandler().  The *keyId* parameter provided with the request
  is the *keyId* parameter provided to DPS_CreateNode().
- The Pre-Shared Key (PSK) and expected identity name via
  DPS_KeyAndIdHandler().  This is requested when the endpoint is
  initiating the DTLS handshake.
- The Pre-Shared Key (PSK) for the current handshake via
  DPS_KeyHandler().  This is requested when the endpoint is responding
  to the DTLS handshake.  The *keyId* parameter provided with the
  request is the *keyId* parameter the initiator provided.

[keystore]: @ref keystore "Key Store"

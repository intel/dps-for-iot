# Access Control

## Publication
When a publication is received, the permissions module is called
to check whether the sender is authorized to send publications.

Permission may be granted based on either the network layer or the
end-to-end layer authenticated identity.  Additionally, individual
topics may be checked.

## Acknowledgement
When an acknowledgement is received, the permissions module is called
to check whether the sender is authorized to send acknowledgements.

Permission may be granted based on either the network layer or the
end-to-end layer authenticated identity.  Additionally, individual
topics may be checked at the publishing node receiving the
acknowledgement.

## Subscription
When a subscription is received, the permissions module is called to
check that the sender is allowed to subscribe.

Subscription checks have several limitations:
- Subscriptions include only a network layer authenticated identity,
  available only when using a transport that supports authenticated
  identities (e.g. DTLS).
- The subscription sender may be a forwarding node, not the original
  subscribing node.  Forwarding nodes aggregate the subscribed topics
  of all downstream nodes so the topics subscribed to by a forwarding
  node identity may include topics subscribed to by other downstream
  identities.
- Permission is granted to all topics in the subscription or none.
  Individual topics cannot be removed from the Bloom filters in the
  subscription.

## Subscription acknowledgement
No permissions check is performed for subscription acknowledgements.

- Subscription acknowledgements include only a network layer
  authenticated identity, available only when using a transport that
  supports authenticated identities (e.g. DTLS).
- Subscription acknowledgements are not forwarded.

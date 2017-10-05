#!/usr/bin/python
import dps
import sys
import time

key_id = [
    [0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2],
    [0x53,0x4d,0x2a,0x4b,0x98,0x76,0x1f,0x25,0x6b,0x78,0x3c,0xc2,0xf8,0x12,0x90,0xcc],
]

# Pre-shared keys for testing only. DO NOT USE THESE KEYS IN A REAL APPLICATION!
key_data = [
    [0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10],
    [0x39,0x12,0x3e,0x7f,0x21,0xbc,0xa3,0x26,0x4e,0x6f,0x3a,0x21,0xa4,0xf1,0xb5,0x98],
]
network_key = [
    0xcd,0xfe,0x31,0x59,0x70,0x5f,0xe4,0xc8,0xcb,0x40,0xac,0x69,0x9c,0x06,0x3a,0x1d
]

key_store = dps.create_memory_key_store()
for i in xrange(len(key_id)):
    dps.set_content_key(key_store, key_id[i], key_data[i])
dps.set_network_key(key_store, network_key)

def on_pub(sub, pub, payload):
    print "Pub %s(%d) matches:" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
    print "  pub " + " | ".join(dps.publication_get_topics(pub))
    print "  sub " + " | ".join(dps.subscription_get_topics(sub))
    print payload
    if dps.publication_is_ack_requested(pub):
        ack_msg = "This is an ACK from %d" % (dps.get_port_number(dps.publication_get_node(pub)))
        print "Sending ack for pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
        print "    %s" % (ack_msg)
        dps.ack_publication(pub, ack_msg);

# Enable or disable (default) DPS debug output
dps.cvar.debug = False

node = dps.create_node("/", dps.memory_key_store_handle(key_store), key_id[0])
dps.start_node(node, dps.MCAST_PUB_ENABLE_RECV, 0)
sub = dps.create_subscription(node, ['a/b/c']);
dps.subscribe(sub, on_pub)

if not sys.flags.interactive:
    while True:
        time.sleep(1)

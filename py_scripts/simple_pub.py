#!/usr/bin/python
import dps
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

key_store = dps.create_memory_key_store()
for i in xrange(len(key_id)):
    dps.set_content_key(key_store, key_id[i], key_data[i])

def on_ack(pub, payload):
    print "Ack for pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
    print "    %s" % (payload)

# Enable or disable (default) DPS debug output
dps.cvar.debug = False

node = dps.create_node("/", dps.memory_key_store_handle(key_store), key_id[0])
dps.start_node(node, dps.MCAST_PUB_ENABLE_SEND, 0)
pub = dps.create_publication(node)

dps.init_publication(pub, ['a/b/c'], False, None, on_ack)
dps.publish(pub, "hello")
print "Pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
time.sleep(0.1)
dps.publish(pub, "world")
print "Pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
time.sleep(0.1)

dps.destroy_publication(pub)
dps.destroy_node(node)
dps.destroy_memory_key_store(key_store)

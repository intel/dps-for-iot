#!/usr/bin/python
import dps
import time

#  Builds this subscription tree
#
#   a/b/c ----\                                   /---- 1/2/3 <----- +/#
#              \                                 /
#   d/e/f ------> A/A -------> B/B <------- C/C <------ 4/5/6
#              /                ^                \
#   g/h/i ----/                 |                 \---- 7/8/9
#                               |
#                              +/#

nodes = {}
subs = {}

key_id = [0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2];
key_data = [0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10];
key_store = dps.create_memory_key_store()
dps.set_content_key(key_store, key_id, key_data)

def on_pub(sub, pub, payload):
    print "Received on port %d" % dps.get_port_number(dps.subscription_get_node(sub))
    print "Subscription ", dps.subscription_get_topic(sub, 0)
    print "  Pub %s/%d" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub))
    print "  Payload %s" % payload

def subscriber(port, topic, connect_port):
    nodes[port] = dps.create_node("/", dps.memory_key_store_handle(key_store), key_id)
    dps.start_node(nodes[port], 0, port)
    subs[port] = dps.create_subscription(nodes[port], [topic])
    dps.subscribe(subs[port], on_pub)
    if (connect_port != 0):
        addr = dps.create_address()
        ret = dps.link_to(nodes[port], None, connect_port, addr)
        if (ret == dps.OK):
            print "Linked %d to %d" % (port, connect_port)
        dps.destroy_address(addr)

# Enable or disable (default) DPS debug output
dps.cvar.debug = False

subscriber(20000, 'B/B', 0)
subscriber(30000, 'A/A', 20000)
subscriber(50000, 'C/C', 20000)

subscriber(40000, 'a/b/c', 30000)
subscriber(40001, 'd/e/f', 30000)
subscriber(40002, 'g/h/i', 30000)

subscriber(60000, '1/2/3', 50000)
subscriber(60001, '4/5/6', 50000)
subscriber(60002, '7/8/9', 50000)

time.sleep(15)
subscriber(0, '+/#', 60000)

time.sleep(15)
subscriber(0, '+/#', 20000)

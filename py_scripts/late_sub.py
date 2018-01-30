#!/usr/bin/python
import dps
import sys
import time

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

node = dps.create_node("/")
dps.start_node(node, dps.MCAST_PUB_ENABLE_RECV + dps.MCAST_PUB_ENABLE_SEND, 0)
permission_store = dps.create_memory_permission_store()
dps.set_permissions(permission_store, dps.WILDCARD_ID, dps.PERM_PUB | dps.PERM_SUB | dps.PERM_ACK)
dps.set_permission_store(node, dps.memory_permission_store_handle(permission_store))
sub = dps.create_subscription(node, ['a/b/c']);
dps.subscribe(sub, on_pub)

time.sleep(1)

# Let publishers know we are here
pub = dps.create_publication(node)
dps.init_publication(pub, ['new_subscriber'], False, None)
dps.publish(pub, "Hi")

if not sys.flags.interactive:
    while True:
        time.sleep(1)

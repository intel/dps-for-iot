#!/usr/bin/python
import dps
import time

def on_pub(sub, new_sub_pub, payload):
    print "Pub %s(%d) matches:" % (dps.publication_get_uuid(new_sub_pub), dps.publication_get_sequence_num(new_sub_pub))
    print "  pub " + " | ".join(dps.publication_get_topics(new_sub_pub))
    print "  sub " + " | ".join(dps.subscription_get_topics(sub))
    print payload
    if dps.publication_is_ack_requested(new_sub_pub):
        ack_msg = "This is an ACK from %d" % (dps.get_port_number(dps.publication_get_node(new_sub_pub)))
        print "Sending ack for pub UUID %s(%d)" % (dps.publication_get_uuid(new_sub_pub), dps.publication_get_sequence_num(new_sub_pub))
        print "    %s" % (ack_msg)
        dps.ack_publication(new_sub_pub, ack_msg);
    dps.publish(pub, "hello")

# Enable or disable (default) DPS debug output
dps.cvar.debug = False

node = dps.create_node("/")
dps.start_node(node, dps.MCAST_PUB_ENABLE_SEND + dps.MCAST_PUB_ENABLE_RECV, 0)
permission_store = dps.create_memory_permission_store()
dps.set_permissions(permission_store, dps.WILDCARD_ID, dps.PERM_PUB | dps.PERM_SUB | dps.PERM_ACK)
dps.set_permission_store(node, dps.memory_permission_store_handle(permission_store))

pub = dps.create_publication(node)
dps.init_publication(pub, ['a/b/c'], False, None)
dps.publish(pub, "hello", 200)

# Subscription for responding to alerts from new subscribers
sub = dps.create_subscription(node, ['new_subscriber']);
dps.subscribe(sub, on_pub)

time.sleep(60)

dps.destroy_publication(pub)
dps.destroy_node(node)

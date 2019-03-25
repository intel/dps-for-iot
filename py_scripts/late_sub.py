#!/usr/bin/python
import dps
import sys
import time

def on_pub(sub, pub, payload):
    print("Pub %s(%d) matches:" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub)))
    print("  pub " + " | ".join(dps.publication_get_topics(pub)))
    print("  sub " + " | ".join(dps.subscription_get_topics(sub)))
    print(payload.tobytes())
    if dps.publication_is_ack_requested(pub):
        ack_msg = "This is an ACK from %s" % (dps.get_listen_address(dps.publication_get_node(pub)))
        print("Sending ack for pub UUID %s(%d)" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub)))
        print("    %s" % (ack_msg))
        dps.ack_publication(pub, ack_msg);

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action='store_true',
                    help="Enable debug ouput if built for debug.")
args = parser.parse_args()
dps.cvar.debug = args.debug

node = dps.create_node("/")
dps.start_node(node, dps.MCAST_PUB_ENABLE_RECV + dps.MCAST_PUB_ENABLE_SEND, None)
print("Subscriber is listening on %s" % (dps.get_listen_address(node)))
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

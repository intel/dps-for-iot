#!/usr/bin/python

import dps
import threading
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

key_id = [
    0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2
]
network_key_id = [
    0x4c,0xfc,0x6b,0x75,0x0f,0x80,0x95,0xb3,0x6c,0xb7,0xc1,0x2f,0x65,0x2d,0x38,0x26
]
key_data = [
    0xf6,0xeb,0xcb,0xa4,0x25,0xdb,0x3b,0x7e,0x73,0x03,0xe6,0x9c,0x60,0x35,0xae,0x11,
    0xae,0x40,0x0b,0x84,0xf0,0x03,0xcc,0xf9,0xce,0x5c,0x5f,0xd0,0xae,0x51,0x0a,0xcc
]
network_key = [
    0x11,0x21,0xbb,0xf4,0x9f,0x5e,0xe5,0x5a,0x11,0x86,0x47,0xe6,0x3d,0xc6,0x59,0xa4,
    0xc3,0x1f,0x16,0x56,0x7f,0x1f,0xb8,0x4d,0xe1,0x09,0x28,0x26,0xd5,0xc0,0xf1,0x34
]
key_store = dps.create_memory_key_store()
dps.set_content_key(key_store, key_id, key_data)
dps.set_network_key(key_store, network_key_id, network_key)

def on_pub(sub, pub, payload):
    print("Received on %s" % dps.get_listen_address(dps.subscription_get_node(sub)))
    print("Pub %s(%d) matches:" % (dps.publication_get_uuid(pub), dps.publication_get_sequence_num(pub)))
    print("  pub " + " | ".join(dps.publication_get_topics(pub)))
    print("  sub " + " | ".join(dps.subscription_get_topics(sub)))
    print(payload.tobytes())

event = threading.Event()
def on_link(node, addr, status):
    if status == dps.OK:
        print("Linked %s to %s" % (dps.get_listen_address(node), addr))
    event.set()

nodes = []
def subscriber(topic, remote_listen_addr):
    node = dps.create_node("/", key_store, None)
    dps.start_node(node, 0, None)
    print("Subscriber is listening on %s" % dps.get_listen_address(node))
    sub = dps.create_subscription(node, [topic])
    dps.subscribe(sub, on_pub)
    if remote_listen_addr != None:
        event.clear()
        ret = dps.link(node, str(remote_listen_addr), on_link)
        if ret == dps.OK:
            event.wait()
    nodes.append(node)
    return node

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-d", "--debug", action='store_true',
                    help="Enable debug ouput if built for debug.")
args = parser.parse_args()
dps.cvar.debug = args.debug

sub1 = subscriber('B/B', None)
sub2 = subscriber('A/A', dps.get_listen_address(sub1))
sub3 = subscriber('C/C', dps.get_listen_address(sub1))

sub4 = subscriber('a/b/c', dps.get_listen_address(sub2))
sub5 = subscriber('d/e/f', dps.get_listen_address(sub2))
sub6 = subscriber('g/h/i', dps.get_listen_address(sub2))

sub7 = subscriber('1/2/3', dps.get_listen_address(sub3))
sub8 = subscriber('4/5/6', dps.get_listen_address(sub3))
sub9 = subscriber('7/8/9', dps.get_listen_address(sub3))

time.sleep(15)
sub10 = subscriber('+/#', dps.get_listen_address(sub7))

time.sleep(15)
sub11 = subscriber('+/#', dps.get_listen_address(sub1))

for node in nodes:
    dps.destroy_node(node)

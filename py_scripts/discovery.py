#!/usr/bin/python
import argparse
import dps
import json
import random
import threading
import time

parser = argparse.ArgumentParser()
parser.add_argument('-d', '--debug', action='store_true',
                    help='Enable debug ouput if built for debug.')

args = parser.parse_args()
dps.cvar.debug = args.debug

class DiscoveryService(threading.Thread):
    _topics = ['$DPS/node']
    def __init__(self, node):
        super(DiscoveryService, self).__init__()
        self._node = node
        self._stop = threading.Event()
    def stop(self):
        self._stop.set()

    def run(self):
        def on_link(node, addr, status):
            if status != dps.ERR_EXISTS:
                print('link %s - %s' % (addr, dps.err_txt(status)))

        def on_ack(pub, payload):
            if dps.match_publications(self._node, payload):
                dps.link(self._node, str(dps.ack_get_sender_address(pub)), on_link)
        self._pub = dps.create_publication(self._node)
        dps.init_publication(self._pub, self._topics, False, None, on_ack)
        dps.publication_set_multicast(self._pub, True)

        self._sub = dps.create_subscription(self._node, self._topics)
        dps.subscription_set_serialize(self._sub, False)
        def on_pub(sub, pub, payload):
            if dps.uuid_compare(dps.publication_get_uuid(self._pub), dps.publication_get_uuid(pub)) == 0:
                # ignore my own publication
                pass
            elif dps.match_publications(self._node, payload):
                dps.link(self._node, str(dps.publication_get_sender_address(pub)), on_link)
            elif dps.publication_is_ack_requested(pub):
                dps.ack_publication_bufs(pub, [dps.serialize_subscriptions(self._node)])
        dps.subscribe(self._sub, on_pub)

        timeout = 1.0
        while True:
            if self._stop.is_set():
                return
            dps.publish_bufs(self._pub, [dps.serialize_subscriptions(self._node)])
            timeout = min(timeout * 2.0, 600.0)
            self._stop.wait(timeout)

        dps.destroy_publication(self._pub)
        dps.destroy_subscription(self._sub)

class Node(object):
    def __init__(self):
        self._node = dps.create_node('/', None, None)
        dps.start_node(self._node, dps.MCAST_PUB_ENABLE_RECV, None)
        self._discovery = DiscoveryService(self._node)
    def get(self):
        return self._node
    def start(self):
        self._discovery.start()
    def stop(self):
        self._discovery.stop()
        self._discovery.join()

class Publisher(Node):
    def __init__(self, topics):
        super(Publisher, self).__init__()
        self._pub = dps.create_publication(self._node)
        dps.init_publication(self._pub, topics, False, None)
    def publish(self, payload, ttl=0):
        dps.publish(self._pub, payload, ttl)

class Subscriber(Node):
    def __init__(self, topics):
        super(Subscriber, self).__init__()
        self._sub = dps.create_subscription(self._node, topics)
        def on_pub(sub, pub, payload):
            print('Pub %s(%d) [%s] matches:' % (dps.publication_get_uuid(pub),
                                                dps.publication_get_sequence_num(pub),
                                                str(dps.publication_get_sender_key_id(pub))))
            print('  pub ' + ' | '.join(dps.publication_get_topics(pub)))
            print('  sub ' + ' | '.join(dps.subscription_get_topics(sub)))
            print(payload.tobytes())
        dps.subscribe(self._sub, on_pub)

def publisher(topics=['A']):
    publisher = Publisher(topics)
    publisher.start()
    return publisher

def subscriber(topics=['A']):
    subscriber = Subscriber(topics)
    subscriber.start()
    return subscriber


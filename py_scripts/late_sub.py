#!/usr/bin/python
import dps
import sys
import time

def OnPub(sub, pub, payload):
    print "Pub %s(%d) matches:" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "  pub " + " | ".join([dps.PublicationGetTopic(pub, i) for i in xrange(dps.PublicationGetNumTopics(pub))])
    print "  sub " + " | ".join([dps.SubscriptionGetTopic(sub, i) for i in xrange(dps.SubscriptionGetNumTopics(sub))])
    print payload
    if dps.PublicationIsAckRequested(pub):
        ackMsg = "This is an ACK from %d" % (dps.GetPortNumber(dps.PublicationGetNode(pub)))
        print "Sending ack for pub UUID %s(%d)" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
        print "    %s" % (ackMsg)
        dps.AckPublication(pub, ackMsg);

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

node = dps.CreateNode("/")
dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV + dps.MCAST_PUB_ENABLE_SEND, 0)
sub = dps.CreateSubscription(node, ['a/b/c']);
dps.Subscribe(sub, OnPub)

time.sleep(1)

# Let publishers know we are here
pub = dps.CreatePublication(node)
dps.InitPublication(pub, ['new_subscriber'], False, None)
dps.Publish(pub, "Hi")

if not sys.flags.interactive:
    while True:
        time.sleep(1)

#!/usr/bin/python
import dps
import time

def OnPub(sub, newSubPub, payload):
    print "Pub %s(%d) matches:" % (dps.PublicationGetUUID(newSubPub), dps.PublicationGetSequenceNum(newSubPub))
    print "  pub " + " | ".join([dps.PublicationGetTopic(newSubPub, i) for i in xrange(dps.PublicationGetNumTopics(newSubPub))])
    print "  sub " + " | ".join([dps.SubscriptionGetTopic(sub, i) for i in xrange(dps.SubscriptionGetNumTopics(sub))])
    print payload
    if dps.PublicationIsAckRequested(newSubPub):
        ackMsg = "This is an ACK from %d" % (dps.GetPortNumber(dps.PublicationGetNode(newSubPub)))
        print "Sending ack for pub UUID %s(%d)" % (dps.PublicationGetUUID(newSubPub), dps.PublicationGetSequenceNum(newSubPub))
        print "    %s" % (ackMsg)
        dps.AckPublication(newSubPub, ackMsg);
    dps.Publish(pub, "hello")

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

node = dps.CreateNode("/")
dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND + dps.MCAST_PUB_ENABLE_RECV, 0)

pub = dps.CreatePublication(node)
dps.InitPublication(pub, ['a/b/c'], False, None)
dps.Publish(pub, "hello", 200)

# Subscription for responding to alerts from new subscribers
sub = dps.CreateSubscription(node, ['new_subscriber']);
dps.Subscribe(sub, OnPub)

time.sleep(60)

dps.DestroyPublication(pub)
dps.DestroyNode(node)

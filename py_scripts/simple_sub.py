import dps
import time

def OnPub(sub, pub, payload):
    print "Pub %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSerialNumber(pub))
    print "Payload %s" % payload
    dps.AckPublication(pub, "Ack for %d" % dps.PublicationGetSerialNumber(pub))


node = dps.CreateNode()
dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, 0)
sub = dps.CreateSubscription(node, ['a/b/c']);
dps.Subscribe(sub, OnPub)

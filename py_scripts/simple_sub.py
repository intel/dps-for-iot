import dps
import time

def OnPub(sub, pub, payload):
    print "Pub %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSerialNumber(pub))
    print "Payload %s" % payload
    ack = dps.CreatePublicationAck(pub);
    dps.AckPublication(ack, "Acking %d" % (dps.PublicationGetSerialNumber(pub)))
    dps.DestroyPublicationAck(ack)

# Set to 1 to enable DPS debug output
dps.cvar.Debug = 0

node = dps.CreateNode()
dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, 0)
sub = dps.CreateSubscription(node, ['a/b/c']);
dps.Subscribe(sub, OnPub)

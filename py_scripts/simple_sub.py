import dps
import time

def OnPub(sub, pub, payload):
    print "Pub %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "Payload %s" % payload
    dps.AckPublication(pub, "Acking %d" % (dps.PublicationGetSequenceNum(pub)))

def OnGetKey(node, kid, key):
    return 0

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

node = dps.CreateNode("/", OnGetKey)
dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, 0)
sub = dps.CreateSubscription(node, ['a/b/c']);
dps.Subscribe(sub, OnPub)

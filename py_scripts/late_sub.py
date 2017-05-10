import dps
import time

def OnPub(sub, pub, payload):
    print "Pub %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "Payload %s" % payload

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

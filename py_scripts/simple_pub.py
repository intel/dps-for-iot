import dps
import time

def OnAck(pub, payload):
    print "PubAck %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "Payload %s" % payload

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

node = dps.CreateNode()
dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND, 0)
pub = dps.CreatePublication(node)

dps.InitPublication(pub, ['a/b/c'], False, OnAck)
dps.Publish(pub, "hello")
time.sleep(0.1)
dps.Publish(pub, "world")
time.sleep(0.1)

dps.DestroyPublication(pub)
dps.DestroyNode(node)

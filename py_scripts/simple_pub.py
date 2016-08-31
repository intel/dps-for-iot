import dps
import time

def OnAck(pub, payload):
    print "PubAck %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSerialNumber(pub))
    print "Payload %s" % payload

# Set to 1 to enable DPS debug output
dps.cvar.Debug = 0

node = dps.CreateNode()
dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND, 0)
pub = dps.CreatePublication(node)

dps.InitPublication(pub, ['a/b/c'], OnAck)
dps.Publish(pub, "hello")
time.sleep(0.1)
dps.Publish(pub, "world")
time.sleep(0.1)

dps.DestroyPublication(pub)
dps.StopNode(node)
dps.DestroyNode(node)

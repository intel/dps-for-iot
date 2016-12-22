import dps
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

nodes = {}
subs = {}

def OnPub(sub, pub, payload):
    print "Received on port %d" % dps.GetPortNumber(dps.SubscriptionGetNode(sub))
    print "Subscription ", dps.SubscriptionGetTopic(sub, 0)
    print "  Pub %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "  Payload %s" % payload

def Subscriber(port, topic, connectPort):
    nodes[port] = dps.CreateNode()
    dps.StartNode(nodes[port], 0, port)
    subs[port] = dps.CreateSubscription(nodes[port], [topic])
    dps.Subscribe(subs[port], OnPub)
    if (connectPort != 0):
        addr = dps.CreateAddress()
        ret = dps.LinkTo(nodes[port], None, connectPort, addr)
        if (ret == dps.OK):
            print "Linked %d to %d" % (port, connectPort)
        dps.DestroyAddress(addr)

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

Subscriber(20000, 'B/B', 0)
Subscriber(30000, 'A/A', 20000)
Subscriber(50000, 'C/C', 20000)

Subscriber(40000, 'a/b/c', 30000)
Subscriber(40001, 'd/e/f', 30000)
Subscriber(40002, 'g/h/i', 30000)

Subscriber(60000, '1/2/3', 50000)
Subscriber(60001, '4/5/6', 50000)
Subscriber(60002, '7/8/9', 50000)

time.sleep(15)
Subscriber(0, '+/#', 60000)

time.sleep(15)
Subscriber(0, '+/#', 20000)

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

keyID = [0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2];

keyData = [0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10];

def OnPub(sub, pub, payload):
    print "Received on port %d" % dps.GetPortNumber(dps.SubscriptionGetNode(sub))
    print "Subscription ", dps.SubscriptionGetTopic(sub, 0)
    print "  Pub %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "  Payload %s" % payload

def OnGetKey(node, kid, key, keylen):
    if cmp(keyID, kid) == 0:
        for k in keyData:
                key.append(k)
        return dps.OK
    else:
        print "kid not equal keyID\n"
        return dps.ERR_MISSING

def Subscriber(port, topic, connectPort):
    nodes[port] = dps.CreateNode("/", OnGetKey, keyID)
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

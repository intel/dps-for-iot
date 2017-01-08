import dps
import time

keyID = [0xed,0x54,0x14,0xa8,0x5c,0x4d,0x4d,0x15,0xb6,0x9f,0x0e,0x99,0x8a,0xb1,0x71,0xf2];

keyData = [0x77,0x58,0x22,0xfc,0x3d,0xef,0x48,0x88,0x91,0x25,0x78,0xd0,0xe2,0x74,0x5c,0x10];

def OnAck(pub, payload):
    print "PubAck %s/%d" % (dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
    print "Payload %s" % payload

def OnGetKey(node, kid, key, keylen):
    if cmp(keyID, kid) == 0:
	for k in keyData:
		key.append(k)
	return 0
    else:
	print "kid not equal keyID\n"
	return 14

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

node = dps.CreateNode("/", OnGetKey, keyID)
dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND, 0)
pub = dps.CreatePublication(node)

dps.InitPublication(pub, ['a/b/c'], False, OnAck)
dps.Publish(pub, "hello")
time.sleep(0.1)
dps.Publish(pub, "world")
time.sleep(0.1)

dps.DestroyPublication(pub)
dps.DestroyNode(node)

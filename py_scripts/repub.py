import dps
import time

# Enable or disable (default) DPS debug output
dps.cvar.Debug = False

node = dps.CreateNode("/")
dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND + dps.MCAST_PUB_ENABLE_RECV, 0)

pub = dps.CreatePublication(node)
dps.InitPublication(pub, ['a/b/c'], False, None)
dps.Publish(pub, "hello", 200)

# Subscription for responding to alerts from new subscribers
sub = dps.CreateSubscription(node, ['new_subscriber']);
def OnNewSub(sub, newSubPub, payload): dps.Publish(pub, "hello")
dps.Subscribe(sub, OnNewSub)

time.sleep(60)

dps.DestroyPublication(pub)
dps.DestroyNode(node)
dps.DestroyMemoryKeyStore(keyStore)

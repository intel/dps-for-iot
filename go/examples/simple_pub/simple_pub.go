package main

import (
	"dps"
	"dps/examples/keys"
	"flag"
	"fmt"
	"time"
)

var (
	debug = flag.Bool("d", false, "enable debug output if built for debug")
	encryption = flag.Int("x", 1, "disable (0) or enable symmetric encryption (1), asymmetric encryption (2), or authentication (3)")
	network = flag.String("n", "udp", "Network of listen and link addresses")
)

func main() {
	flag.Parse()
	if *debug {
		dps.SetDebug(1)
	} else {
		dps.SetDebug(0)
	}
	var nodeId, pubKeyId []byte
	keyStore := dps.CreateMemoryKeyStore()
	dps.SetNetworkKey(keyStore, keys.NetworkKeyId, keys.NetworkKey)
	if *encryption == 0 {
		nodeId = nil
		pubKeyId = nil
	} else if *encryption == 1 {
		for i := 0; i < len(keys.KeyId); i++ {
			dps.SetContentKey(keyStore, keys.KeyId[i], keys.KeyData[i])
		}
		nodeId = nil
		pubKeyId = keys.KeyId[0]
	} else if *encryption == 2 {
		dps.SetTrustedCA(keyStore, keys.CA)
		dps.SetCertificate(keyStore, keys.PublisherCert, &keys.PublisherPrivateKey, &keys.PublisherPassword)
		dps.SetCertificate(keyStore, keys.SubscriberCert, nil, nil)
		nodeId = []byte(keys.PublisherId)
		pubKeyId = []byte(keys.SubscriberId)
	}

	node := dps.CreateNode("/", keyStore, nodeId)
	addr := dps.CreateAddress()
	dps.SetAddress(addr, network, nil)
	dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND, addr)
	dps.DestroyAddress(addr)
	fmt.Printf("Publisher is listening on %v\n", dps.GetListenAddressString(node))

	pub := dps.CreatePublication(node)

	dps.InitPublication(pub, []string{"a/b/c"}, false, nil, func(pub *dps.Publication, payload []byte) {
		fmt.Printf("Ack for pub UUID %v(%v)\n", dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
		fmt.Printf("    %v\n", string(payload))
	})
	dps.PublicationAddSubId(pub, pubKeyId)
	dps.Publish(pub, []byte("hello"), 0)
	fmt.Printf("Pub UUID %v(%v)\n", dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
	time.Sleep(100 * time.Millisecond)
	dps.Publish(pub, []byte("world"), 0)
	fmt.Printf("Pub UUID %v(%v)\n", dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
	time.Sleep(100 * time.Millisecond)

	dps.DestroyPublication(pub)
	dps.DestroyNode(node, func(node *dps.Node) {
		dps.DestroyKeyStore(keyStore)
	})
}

package main

import (
	"dps"
	"dps/examples/keys"
	"fmt"
	"os"
	"strconv"
	"time"
)

func main() {
	dps.SetDebug(0)
	encryption := 1
	for i := 0; i < len(os.Args); i++ {
		if os.Args[i] == "-x" {
			i++
			encryption, _ = strconv.Atoi(os.Args[i])
		} else if os.Args[i] == "-d" {
			dps.SetDebug(1)
		}
	}

	var nodeId, pubKeyId []byte
	keyStore := dps.CreateMemoryKeyStore()
	dps.SetNetworkKey(keyStore, keys.NetworkKeyId, keys.NetworkKey)
	if encryption == 0 {
		nodeId = nil
		pubKeyId = nil
	} else if encryption == 1 {
		for i := 0; i < len(keys.KeyId); i++ {
			dps.SetContentKey(keyStore, keys.KeyId[i], keys.KeyData[i])
		}
		nodeId = nil
		pubKeyId = keys.KeyId[0]
	} else if encryption == 2 {
		dps.SetTrustedCA(keyStore, keys.CA)
		dps.SetCertificate(keyStore, keys.PublisherCert, &keys.PublisherPrivateKey, &keys.PublisherPassword)
		dps.SetCertificate(keyStore, keys.SubscriberCert, nil, nil)
		nodeId = []byte(keys.PublisherId)
		pubKeyId = []byte(keys.SubscriberId)
	}

	node := dps.CreateNode("/", keyStore, nodeId)
	dps.StartNode(node, dps.MCAST_PUB_ENABLE_SEND, nil)
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

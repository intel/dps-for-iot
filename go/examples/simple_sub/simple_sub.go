package main

import (
	"dps"
	"dps/examples/keys"
	"fmt"
	"os"
	"strconv"
	"strings"
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

	var nodeId []byte
	keyStore := dps.CreateMemoryKeyStore()
	dps.SetNetworkKey(keyStore, keys.NetworkKeyId, keys.NetworkKey)
	if encryption == 0 {
		nodeId = nil
	} else if encryption == 1 {
		for i := 0; i < len(keys.KeyId); i++ {
			dps.SetContentKey(keyStore, keys.KeyId[i], keys.KeyData[i])
		}
		nodeId = nil
	} else if encryption == 2 {
		dps.SetTrustedCA(keyStore, keys.CA)
		dps.SetCertificate(keyStore, keys.SubscriberCert, &keys.SubscriberPrivateKey, &keys.SubscriberPassword)
		dps.SetCertificate(keyStore, keys.PublisherCert, nil, nil)
		nodeId = []byte(keys.SubscriberId)
	}

	node := dps.CreateNode("/", keyStore, nodeId)
	dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, nil)
	fmt.Printf("Subscriber is listening on %v\n", dps.GetListenAddressString(node))

	sub := dps.CreateSubscription(node, []string{"a/b/c"})
	dps.Subscribe(sub, func(sub *dps.Subscription, pub *dps.Publication, payload []byte) {
		fmt.Printf("Pub %v(%v) matches:\n", dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
		fmt.Printf("  pub %v\n", strings.Join(dps.PublicationGetTopics(pub), " | "))
		fmt.Printf("  sub %v\n", strings.Join(dps.SubscriptionGetTopics(sub), " | "))
		fmt.Printf("%v\n", string(payload))
		if dps.PublicationIsAckRequested(pub) {
			ackMsg := fmt.Sprintf("This is an ACK from %v", dps.GetListenAddressString(node))
			fmt.Printf("Sending ack for pub UUID %v(%v)\n", dps.PublicationGetUUID(pub), dps.PublicationGetSequenceNum(pub))
			fmt.Printf("    %v\n", ackMsg)
			dps.AckPublication(pub, []byte(ackMsg))
		}
	})

	for {
		time.Sleep(1 * time.Second)
	}
}

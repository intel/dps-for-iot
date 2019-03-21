package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"dps"
	"dps/examples/keys"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func pad(in []byte, n int) (out []byte) {
	out = make([]byte, n)
	low := len(out) - len(in)
	copy(out[low:], in)
	return
}

func main() {
	onKeyAndId := func(request *dps.KeyStoreRequest) int {
		return dps.SetKeyAndId(request, dps.KeySymmetric(keys.NetworkKey), keys.NetworkKeyId)
	}
	onKey := func(request *dps.KeyStoreRequest, id dps.KeyId) int {
		for i := 0; i < len(keys.KeyId); i++ {
			if bytes.Compare(keys.KeyId[i], id) == 0 {
				return dps.SetKey(request, dps.KeySymmetric(keys.KeyData[i]))
			}
		}
		if bytes.Compare(keys.NetworkKeyId, id) == 0 {
			return dps.SetKey(request, dps.KeySymmetric(keys.NetworkKey))
		}
		if bytes.Compare([]byte(keys.PublisherId), id) == 0 {
			return dps.SetKey(request, dps.KeyCert{keys.PublisherCert, "", ""})
		}
		if bytes.Compare([]byte(keys.SubscriberId), id) == 0 {
			return dps.SetKey(request, dps.KeyCert{keys.SubscriberCert, keys.SubscriberPrivateKey, keys.SubscriberPassword})
		}
		return dps.ERR_MISSING
	}
	onEphemeralKey := func(request *dps.KeyStoreRequest, key dps.Key) int {
		switch key.(type) {
		case dps.KeySymmetric:
			k := make([]byte, 32)
			_, err := rand.Read(k)
			if err != nil {
				return dps.ERR_FAILURE
			}
			return dps.SetKey(request, dps.KeySymmetric(k))
		case dps.KeyEC:
			var curve elliptic.Curve
			keyEC, _ := key.(dps.KeyEC)
			if keyEC.Curve == dps.EC_CURVE_P384 {
				curve = elliptic.P384()
			} else if keyEC.Curve == dps.EC_CURVE_P521 {
				curve = elliptic.P521()
			}
			d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
			if err != nil {
				return dps.ERR_FAILURE
			}
			n := (curve.Params().BitSize + 7) / 8
			return dps.SetKey(request, dps.KeyEC{keyEC.Curve, pad(x.Bytes(), n), pad(y.Bytes(), n), pad(d, n)})
		default:
			return dps.ERR_MISSING
		}
	}
	onCA := func(request *dps.KeyStoreRequest) int {
		return dps.SetCA(request, keys.CA)
	}

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

	var keyStore dps.KeyStore
	var nodeId []byte
	if encryption == 0 {
		keyStore = dps.CreateKeyStore(onKeyAndId, onKey, onEphemeralKey, nil)
		nodeId = nil
	} else if encryption == 1 {
		keyStore = dps.CreateKeyStore(onKeyAndId, onKey, onEphemeralKey, nil)
		nodeId = nil
	} else if encryption == 2 {
		keyStore = dps.CreateKeyStore(onKeyAndId, onKey, onEphemeralKey, onCA)
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

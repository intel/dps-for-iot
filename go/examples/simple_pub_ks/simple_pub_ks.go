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
			return dps.SetKey(request, dps.KeyCert{keys.PublisherCert, keys.PublisherPrivateKey, keys.PublisherPassword})
		}
		if bytes.Compare([]byte(keys.SubscriberId), id) == 0 {
			return dps.SetKey(request, dps.KeyCert{keys.SubscriberCert, "", ""})
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
	var nodeId, pubKeyId []byte
	if encryption == 0 {
		keyStore = dps.CreateKeyStore(onKeyAndId, onKey, onEphemeralKey, nil)
		nodeId = nil
		pubKeyId = nil
	} else if encryption == 1 {
		keyStore = dps.CreateKeyStore(onKeyAndId, onKey, onEphemeralKey, nil)
		nodeId = nil
		pubKeyId = keys.KeyId[0]
	} else if encryption == 2 {
		keyStore = dps.CreateKeyStore(onKeyAndId, onKey, onEphemeralKey, onCA)
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

package main

import (
	"dps"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/pprof"
	"sync"
)

var (
	debug = flag.Bool("d", false, "enable debug output if built for debug")
	listenText = flag.Int("p", 0, "address to link")
	payloadSize = flag.Int("s", 0, "size of PUB payload")
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	lock = sync.Mutex{}
	cond = sync.NewCond(&lock)
	payload []byte
)

func onPubMatch(sub *dps.Subscription, pub *dps.Publication, data []byte) {
	if dps.PublicationIsAckRequested(pub) {
		var ret int
		if *payloadSize < 0 {
			ret = dps.AckPublication(pub, data)
		} else {
			ret = dps.AckPublication(pub, payload)
		}
		if ret != dps.OK {
			fmt.Printf("Failed to ack pub %v\n", dps.ErrTxt(ret))
		}
	}
}

func main() {
	flag.Parse()
	if *debug {
		dps.SetDebug(1)
	} else {
		dps.SetDebug(0)
	}
	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	node := dps.CreateNode("/", nil, nil)
	listenAddr := dps.CreateAddress()
	dps.SetAddress(listenAddr, fmt.Sprintf(":%v", *listenText))
	dps.StartNode(node, dps.MCAST_PUB_ENABLE_RECV, listenAddr)
	fmt.Printf("Subscriber is listening on %v\n", dps.GetListenAddressString(node))

	if *payloadSize > 0 {
		payload = make([]byte, *payloadSize)
	}

	sub := dps.CreateSubscription(node, []string{"dps/roundtrip"})
	dps.Subscribe(sub, onPubMatch)

	lock.Lock()
	cond.Wait()
	lock.Unlock()

	dps.DestroySubscription(sub)
	dps.DestroyNode(node, func(node *dps.Node) {})
	dps.DestroyAddress(listenAddr)
}

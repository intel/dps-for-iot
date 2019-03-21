package main

import (
	"dps"
	"flag"
	"fmt"
	"math"
	"log"
	"os"
	"runtime/pprof"
	"sync"
	"time"
)

var (
	debug = flag.Bool("d", false, "enable debug output if built for debug")
	linkText = flag.String("p", "", "address to link")
	payloadSize = flag.Int("s", 0, "size of PUB payload")
	numPubs = flag.Int("n", 1000, "number of publications to send")
	cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	rtTime time.Duration
	prev time.Time
	lock = sync.Mutex{}
	cond = sync.NewCond(&lock)
	ackReceived = false
)

func elapsedTime() (elapsed time.Duration) {
	now := time.Now()
	elapsed = now.Sub(prev)
	prev = now
	return
}

func onAck(pub *dps.Publication, payload []byte) {
	rtTime = elapsedTime()
	lock.Lock()
	ackReceived = true
	cond.Signal()
	lock.Unlock()
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

	mcast := dps.MCAST_PUB_ENABLE_SEND
	if *linkText != "" {
		mcast = dps.MCAST_PUB_DISALBED
	}

	node := dps.CreateNode("/", nil, nil)
	dps.StartNode(node, mcast, nil)

	if *linkText != "" {
		err := dps.LinkTo(node, *linkText, nil)
		if err != dps.OK {
			fmt.Printf("dps.LinkTo %v returned %s\n", *linkText, dps.ErrTxt(err))
			return
		}
	}

	rtMin := time.Duration(math.MaxInt64)
	var rtMax, rtSum time.Duration

	pub := dps.CreatePublication(node)
	dps.InitPublication(pub, []string{"dps/roundtrip"}, false, nil, onAck)
	var payload []byte
	if *payloadSize != 0 {
		payload = make([]byte, *payloadSize)
	}
	for i := 0; i < *numPubs; i++ {
		lock.Lock()
		ackReceived = false
		lock.Unlock()
		elapsedTime() // Initialize the round trip timer
		dps.Publish(pub, payload, 0)
		lock.Lock()
		for !ackReceived {
			cond.Wait()
		}
		lock.Unlock()
		if i != 0 {
			if rtTime > rtMax {
				rtMax = rtTime
			}
			if rtTime < rtMin {
				rtMin = rtTime
			}
			rtSum += rtTime
		}
	}

	fmt.Printf("Total pub sent = %v, payload size %v\n", *numPubs, *payloadSize)
	fmt.Printf("Min RT = %v, Max RT = %v, Avg RT %v\n", rtMin, rtMax,
		time.Duration(rtSum.Nanoseconds() / int64(*numPubs)))
	dps.DestroyPublication(pub)
	dps.DestroyNode(node, func(node *dps.Node) {})
}

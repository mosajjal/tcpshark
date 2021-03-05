package main

import (
	"fmt"
	"log"
	"time"

	"os"
	"os/signal"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// CaptureOptions is a set of generated options variables to use within our capture routine
// type CaptureOptions struct {
// 	DevName       string
// 	useAfpacket   bool
// 	PcapFile      string
// 	Filter        string
// 	Port          uint16
// 	GcTime        time.Duration
// 	ResultChannel chan<- captureResult
// 	Done          chan bool
// }

func initializeLivePcap(devName, filter string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, true, pcap.BlockForever)
	errorHandler(err)

	// Set Filter
	log.Printf("Using Device: %s\n", devName)
	log.Printf("Filter: %s\n", filter)
	err = handle.SetBPFFilter(filter)
	errorHandler(err)

	return handle
}

func handleInterrupt(done chan bool) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			log.Printf("SIGINT received")
			close(done)
			return
		}
	}()
}

func start(DevName string, pbf string) {
	handle := initializeLivePcap(DevName, pbf)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	packetSource.DecodeOptions.Lazy = true
	packetSource.NoCopy = true

	for {
		select {
		case packet := <-packetSource.Packets():
			if packet == nil {
				log.Println("PacketSource returned nil, exiting (Possible end of pcap file?). Sleeping for 10 seconds waiting for processing to finish")
				time.Sleep(time.Second * 10)
				// close(options.Done)
				return
			}
			fmt.Println(packet)
			// case <-options.Done:
			// 	return
			// case <-captureStatsTicker:
			// 	if handle != nil {
			// 		mystats, err := handle.Stats()
			// 		if err == nil {
			// 			pcapStats.PacketsGot = mystats.PacketsReceived
			// 			pcapStats.PacketsLost = mystats.PacketsDropped
			// 		} else {
			// 			pcapStats.PacketsGot = totalCnt
			// 		}
			// 	} else {
			// 		updateAfpacketStats(afhandle)
			// 	}
			// 	pcapStats.PacketLossPercent = (float32(pcapStats.PacketsLost) * 100.0 / float32(pcapStats.PacketsGot))

			// case <-printStatsTicker:
			// 	log.Printf("%+v\n", pcapStats)

		}

	}
}

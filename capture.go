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

		}

	}
}

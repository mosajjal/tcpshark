package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func errorHandler(err error) {
	if err != nil {
		log.Fatal("fatal Error: ", err)
	}
}

var outputChannel = make(chan gopacket.Packet, 100)

func main() {
	go printPacket(outputChannel)
	// pid, process name, process full path, time, start, user
	// fmt.Println(process.Processes())
	// pid, source address, source port, dest address, dest port, status
	// fmt.Println(net.Interfaces())
	// start capture
	start("lo", "icmp")
	// correlate source and dest socket from each packet to the network, find the pid and add context of the pid to the packet "data"
	// ???
	// push this somehow to pcap-ng or sth
	// profit?
}

func initializeOutputPcap(filePath string) *pcapgo.NgWriter {
	f, _ := os.OpenFile(filePath, os.O_APPEND, 0700)
	w, _ := pcapgo.NewNgWriter(f, 1)
	return w
}

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

func printPacket(packet chan gopacket.Packet) {
	writer := initializeOutputPcap("./test.pcapng")
	for {
		select {
		case p := <-packet:
			fmt.Println("here")
			writer.WritePacket(p.Metadata().CaptureInfo, p.Data())
			writer.Flush()
		}

	}
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
			outputChannel <- packet

		}

	}
}

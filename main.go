package main

import (
	"fmt"
	"log"

	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func errorHandler(err error) {
	if err != nil {
		log.Fatal("fatal Error: ", err)
	}
}

func main() {
	// pid, process name, process full path, time, start, user
	fmt.Println(process.Processes())
	// pid, source address, source port, dest address, dest port, status
	fmt.Println(net.Interfaces())
	// start capture
	start("lo", "icmp")
	// correlate source and dest socket from each packet to the network, find the pid and add context of the pid to the packet "data"
	// ???
	// push this somehow to pcap-ng or sth
	// profit?
}

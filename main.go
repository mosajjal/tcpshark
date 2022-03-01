package main

import (
	"bytes"
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/drael/GOnetstat"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	flags "github.com/jessevdk/go-flags"
	"github.com/lunixbochs/struc"
	"github.com/shirou/gopsutil/process"
)

const TcpSharkMagic = 0xA1BFF3D4

// maps source port and dest port to a pid
var GlobalProcessLookup = make(map[PacketMetaDataKey]PacketMetaData)

type PacketMetaDataKey struct {
	LocalPort, RemotePort uint16
}

type PacketMetaData struct {
	Magic   uint32 `struc:"int32"`
	Pid     uint32 `struc:"uint32"`
	CmdLen  uint8  `struc:"uint8,sizeof=Cmd"` // max Cmd is 255 chars
	Cmd     string
	ArgsLen uint16 `struc:"uint16,sizeof=Args"` // max args is 65535 chars
	Args    string
}

func initializeLivePcap(devName, filter string) *pcap.Handle {
	// Open device
	handle, err := pcap.OpenLive(devName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	// Set Filter
	log.Printf("Using Device: %s\n", devName)
	log.Printf("Filter: %s\n", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	return handle
}
func handleInterrupt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			for {
				log.Println("SIGINT Received. Stopping capture...")
				os.Exit(0)
			}
		}
	}()
}
func lookupProcess(verbosity uint8, srcPort uint16, dstPort uint16) PacketMetaData {
	localProcess := GlobalProcessLookup[PacketMetaDataKey{srcPort, dstPort}]
	switch verbosity {
	case 0:
		localProcess.CmdLen = 0
		localProcess.Cmd = ""
	case 2:
		// read cmdline from /proc/pid/cmdline
		p, _ := process.NewProcess(int32(localProcess.Pid))
		cmdline, _ := p.Cmdline()
		localProcess.ArgsLen = uint16(len(cmdline))
		localProcess.Args = cmdline
	}

	return localProcess
}

var GeneralOptions struct {
	OutFile   flags.Filename `long:"outfile"   short:"o"                 required:"true"  description:"Output pcap file path" `
	Interface string         `long:"interface" short:"i"    default:"lo" required:"true"  description:"Interface to use. Only supports Ethernet type packets interfaces. Do not use it on SPANs"`
	Bpf       string         `long:"bpf"       short:"f"    default:""   required:"false" description:"tcpdump-style BPF filter"`
	Verbosity uint8          `long:"verbosity" short:"v"    default:"1"  required:"false" description:"Verbosity of the metadata: 0 - only pid, 1 - pid and cmd, 2 - pid, cmd and args"`
}

func main() {

	var parser = flags.NewNamedParser("tcpshark", flags.PassDoubleDash|flags.PrintErrors|flags.HelpFlag)
	parser.AddGroup("tcpshark", "tcpshark Options", &GeneralOptions)
	_, err := parser.Parse()
	if err != nil {
		os.Exit(-1)
	}

	f, err := os.OpenFile(string(GeneralOptions.OutFile), os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	outputHandle, err := pcapgo.NewNgWriter(f, 1)
	if err != nil {
		panic(err)
	}
	//generate a packet

	inputHandle := initializeLivePcap(GeneralOptions.Interface, GeneralOptions.Bpf)
	handleInterrupt()

	// reload the process lookup table every second
	go func() {

		for range time.Tick(time.Second) {
			plookup := make(map[PacketMetaDataKey]PacketMetaData)
			connData := GOnetstat.Tcp()
			connData = append(connData, GOnetstat.Udp()...)
			for _, c := range connData {
				pid, _ := strconv.Atoi(c.Pid)
				plookup[PacketMetaDataKey{uint16(c.Port), uint16(c.ForeignPort)}] = PacketMetaData{
					Magic:   TcpSharkMagic,
					Pid:     uint32(pid),
					CmdLen:  uint8(len(c.Exe)),
					Cmd:     c.Name,
					ArgsLen: 0,
					Args:    "",
				}
			}
			GlobalProcessLookup = plookup
		}

	}()

	// now := time.Now()
	for {
		packet, _, err := inputHandle.ReadPacketData()
		if err != nil {
			log.Fatal(err)
		}

		ethPacket := gopacket.NewPacket(
			packet,
			layers.LayerTypeEthernet,
			gopacket.Default,
		)

		oldEthLayer := ethPacket.Layers()[0].(*layers.Ethernet)

		//subtract oldethelayer from the begining of ethpacket
		restOfLayers := ethPacket.Layers()[1:]
		remainder := []byte{}
		metadata := PacketMetaData{}
		for _, layer := range restOfLayers {
			// we can correlate metadata only in TCP or UDP for now
			remainder = append(remainder, layer.LayerContents()...)
			if layer.LayerType() == layers.LayerTypeTCP {
				tcpLayer := layer.(*layers.TCP)
				metadata = lookupProcess(GeneralOptions.Verbosity, uint16(tcpLayer.SrcPort), uint16(tcpLayer.DstPort))
			}
			if layer.LayerType() == layers.LayerTypeUDP {
				udpLayer := layer.(*layers.UDP)
				metadata = lookupProcess(GeneralOptions.Verbosity, uint16(udpLayer.SrcPort), uint16(udpLayer.DstPort))
			}
		}
		var packetTrailer bytes.Buffer
		_ = struc.Pack(&packetTrailer, &metadata)
		newEtherLayer := &EthernetWithTrailer{
			SrcMAC:       oldEthLayer.SrcMAC,
			DstMAC:       oldEthLayer.DstMAC,
			EthernetType: oldEthLayer.EthernetType,
			Trailer:      packetTrailer.Bytes(),
		}
		buffer := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, newEtherLayer, gopacket.Payload(remainder))

		err = outputHandle.WritePacket(gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			Length:        len(buffer.Bytes()),
			CaptureLength: len(buffer.Bytes()),
		}, buffer.Bytes())
		if err != nil {
			panic(err)
		}
		outputHandle.Flush()

	}

}

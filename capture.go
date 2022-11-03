package main

import (
	"bytes"
	"os"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/lunixbochs/struc"
)

type packetMetaDataKey struct {
	LocalPort, RemotePort uint16
}

type packetMetaData struct {
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
		log.Fatal().Msg(err.Error())
	}

	// Set Filter
	log.Info().Msgf("Using Device: %s", devName)
	log.Info().Msgf("Filter: %s", filter)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	return handle
}

// blocking function to grab packets
func capture() {
	// set up inpput handle
	var outputHandle *pcapgo.NgWriter
	if generalOptions.OutFile == "-" {
		var err error
		outputHandle, err = pcapgo.NewNgWriter(os.Stdout, 1)
		if err != nil {
			panic(err)
		}
	} else {
		f, err := os.OpenFile(string(generalOptions.OutFile), os.O_RDWR|os.O_CREATE, 0o755)
		if err != nil {
			log.Warn().Msg(err.Error())
		}
		defer f.Close()
		outputHandle, err = pcapgo.NewNgWriter(f, 1)
		if err != nil {
			panic(err)
		}
		// generate a packet
	}
	inputHandle := initializeLivePcap(generalOptions.Interface, generalOptions.Bpf)

	for {
		packet, _, err := inputHandle.ReadPacketData()
		if err != nil {
			log.Fatal().Msg(err.Error())
		}

		ethPacket := gopacket.NewPacket(
			packet,
			layers.LayerTypeEthernet,
			gopacket.Default,
		)

		oldEthLayer := ethPacket.Layers()[0].(*layers.Ethernet)

		// subtract oldethelayer from the begining of ethpacket
		restOfLayers := ethPacket.Layers()[1:]
		remainder := []byte{}
		metadata := packetMetaData{}
		for _, layer := range restOfLayers {
			// we can correlate metadata only in TCP or UDP for now
			remainder = append(remainder, layer.LayerContents()...)
			if layer.LayerType() == layers.LayerTypeTCP {
				tcpLayer := layer.(*layers.TCP)
				metadata = lookupProcess(generalOptions.Verbosity, uint16(tcpLayer.SrcPort), uint16(tcpLayer.DstPort))
			}
			if layer.LayerType() == layers.LayerTypeUDP {
				udpLayer := layer.(*layers.UDP)
				metadata = lookupProcess(generalOptions.Verbosity, uint16(udpLayer.SrcPort), uint16(udpLayer.DstPort))
			}
		}
		var packetTrailer bytes.Buffer
		err = struc.Pack(&packetTrailer, &metadata)
		if err != nil {
			log.Warn().Msg(err.Error())
		}
		newEtherLayer := &EthernetWithTrailer{
			SrcMAC:       oldEthLayer.SrcMAC,
			DstMAC:       oldEthLayer.DstMAC,
			EthernetType: oldEthLayer.EthernetType,
			Trailer:      packetTrailer.Bytes(),
		}

		buffer := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, newEtherLayer, gopacket.Payload(remainder))
		if err != nil {
			log.Warn().Msg(err.Error())
		}

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

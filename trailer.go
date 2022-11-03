package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// EthernetBroadcast is the broadcast MAC address used by Ethernet.
// var EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// EthernetWithTrailer is the layer for Ethernet frame headers.
type EthernetWithTrailer struct {
	layers.BaseLayer
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   layers.EthernetType
	// Length is only set if a length field exists within this header.  Ethernet
	// headers follow two different standards, one that uses an EthernetType, the
	// other which defines a length the follows with a LLC header (802.3).  If the
	// former is the case, we set EthernetType and Length stays 0.  In the latter
	// case, we set Length and EthernetType = EthernetTypeLLC.
	Length  uint16
	Trailer []byte
}

// LayerType returns LayerTypeEthernet
func (e *EthernetWithTrailer) LayerType() gopacket.LayerType { return layers.LayerTypeEthernet }

func (e *EthernetWithTrailer) linkFlow() gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointMAC, e.SrcMAC, e.DstMAC)
}

func (e *EthernetWithTrailer) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}
	e.DstMAC = net.HardwareAddr(data[0:6])
	e.SrcMAC = net.HardwareAddr(data[6:12])
	e.EthernetType = layers.EthernetType(binary.BigEndian.Uint16(data[12:14]))
	e.BaseLayer = layers.BaseLayer{data[:14], data[14:]}
	e.Length = 0
	if e.EthernetType < 0x0600 {
		e.Length = uint16(e.EthernetType)
		e.EthernetType = layers.EthernetTypeLLC
		if cmp := len(e.Payload) - int(e.Length); cmp < 0 {
			df.SetTruncated()
		} else if cmp > 0 {
			// Strip off bytes at the end, since we have too many bytes
			e.Payload = e.Payload[:len(e.Payload)-cmp]
		}
		//	fmt.Println(eth)
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (e *EthernetWithTrailer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if len(e.DstMAC) != 6 {
		return fmt.Errorf("invalid dst MAC: %v", e.DstMAC)
	}
	if len(e.SrcMAC) != 6 {
		return fmt.Errorf("invalid src MAC: %v", e.SrcMAC)
	}
	payload := b.Bytes()
	bytes, err := b.PrependBytes(14)
	if err != nil {
		return err
	}
	copy(bytes, e.DstMAC)
	copy(bytes[6:], e.SrcMAC)
	if e.Length != 0 || e.EthernetType == layers.EthernetTypeLLC {
		if opts.FixLengths {
			e.Length = uint16(len(payload))
		}
		if e.EthernetType != layers.EthernetTypeLLC {
			return fmt.Errorf("ethernet type %v not compatible with length value %v", e.EthernetType, e.Length)
		} else if e.Length > 0x0600 {
			return fmt.Errorf("invalid ethernet length %v", e.Length)
		}
		binary.BigEndian.PutUint16(bytes[12:], e.Length)
	} else {
		binary.BigEndian.PutUint16(bytes[12:], uint16(e.EthernetType))
	}
	length := len(b.Bytes())
	if length < 60 {
		// Pad out to 60 bytes.
		padding, err := b.AppendBytes(60 - length)
		if err != nil {
			return err
		}
		copy(padding, lotsOfZeros[:])
	}

	//todo: find a way to put the trailer here
	trailer, err := b.AppendBytes(len(e.Trailer))
	if err != nil {
		return err
	}
	copy(trailer, e.Trailer)
	// todo: some of this gets gobbled up as framecheck sequence, putting a 4 byte 0 in the trailer to avoid that
	checksum, err := b.AppendBytes(4)
	if err != nil {
		return err
	}
	copy(checksum, lotsOfZeros[:])
	return nil
}

func (e *EthernetWithTrailer) canDecode() gopacket.LayerClass {
	return layers.LayerTypeEthernet
}

func (e *EthernetWithTrailer) nextLayerType() gopacket.LayerType {
	return e.EthernetType.LayerType()
}

var lotsOfZeros [1024]byte

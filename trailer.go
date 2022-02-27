package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// EthernetBroadcast is the broadcast MAC address used by Ethernet.
var EthernetBroadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// Ethernet is the layer for Ethernet frame headers.
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

func (e *EthernetWithTrailer) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(layers.EndpointMAC, e.SrcMAC, e.DstMAC)
}

func (eth *EthernetWithTrailer) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 14 {
		return errors.New("Ethernet packet too small")
	}
	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.EthernetType = layers.EthernetType(binary.BigEndian.Uint16(data[12:14]))
	eth.BaseLayer = layers.BaseLayer{data[:14], data[14:]}
	eth.Length = 0
	if eth.EthernetType < 0x0600 {
		eth.Length = uint16(eth.EthernetType)
		eth.EthernetType = layers.EthernetTypeLLC
		if cmp := len(eth.Payload) - int(eth.Length); cmp < 0 {
			df.SetTruncated()
		} else if cmp > 0 {
			// Strip off bytes at the end, since we have too many bytes
			eth.Payload = eth.Payload[:len(eth.Payload)-cmp]
		}
		//	fmt.Println(eth)
	}
	return nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
// See the docs for gopacket.SerializableLayer for more info.
func (eth *EthernetWithTrailer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if len(eth.DstMAC) != 6 {
		return fmt.Errorf("invalid dst MAC: %v", eth.DstMAC)
	}
	if len(eth.SrcMAC) != 6 {
		return fmt.Errorf("invalid src MAC: %v", eth.SrcMAC)
	}
	payload := b.Bytes()
	bytes, err := b.PrependBytes(14)
	if err != nil {
		return err
	}
	copy(bytes, eth.DstMAC)
	copy(bytes[6:], eth.SrcMAC)
	if eth.Length != 0 || eth.EthernetType == layers.EthernetTypeLLC {
		if opts.FixLengths {
			eth.Length = uint16(len(payload))
		}
		if eth.EthernetType != layers.EthernetTypeLLC {
			return fmt.Errorf("ethernet type %v not compatible with length value %v", eth.EthernetType, eth.Length)
		} else if eth.Length > 0x0600 {
			return fmt.Errorf("invalid ethernet length %v", eth.Length)
		}
		binary.BigEndian.PutUint16(bytes[12:], eth.Length)
	} else {
		binary.BigEndian.PutUint16(bytes[12:], uint16(eth.EthernetType))
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
	trailer, err := b.AppendBytes(len(eth.Trailer))
	if err != nil {
		return err
	}
	copy(trailer, eth.Trailer)
	// todo: some of this gets gobbled up as framecheck sequence, putting a 4 byte 0 in the trailer to avoid that
	checksum, err := b.AppendBytes(4)
	if err != nil {
		return err
	}
	copy(checksum, lotsOfZeros[:])
	return nil
}

func (eth *EthernetWithTrailer) CanDecode() gopacket.LayerClass {
	return layers.LayerTypeEthernet
}

func (eth *EthernetWithTrailer) NextLayerType() gopacket.LayerType {
	return eth.EthernetType.LayerType()
}

var lotsOfZeros [1024]byte

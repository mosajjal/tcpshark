package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/google/gopacket/pcap"
	flags "github.com/jessevdk/go-flags"
	"github.com/mosajjal/tcpshark/netstat"
	"github.com/shirou/gopsutil/process"
)

const TcpSharkMagic = 0xA1BFF3D4

// maps source port and dest port to a pid
var GlobalProcessLookup = make(map[PacketMetaDataKey]PacketMetaData)

func handleInterrupt() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	if runtime.GOOS == "linux" {
		signal.Notify(c, syscall.SIGPIPE)
	}
	go func() {
		for range c {
			for {
				log.Info().Msg("SIGINT Received. Stopping capture...")
				os.Exit(0)
			}
		}
	}()
}

func lookupProcess(verbosity uint8, srcPort uint16, dstPort uint16) PacketMetaData {
	localProcess := GlobalProcessLookup[PacketMetaDataKey{srcPort, dstPort}]
	localProcess.Magic = TcpSharkMagic
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

//go:embed tcpshark.lua
var tcpsharkLua string

var GeneralOptions struct {
	OutFile        flags.Filename `long:"outfile"         short:"o"                 required:"true"  description:"Output pcap file path. Use '-' for stdout" `
	Interface      string         `long:"interface"       short:"i"    default:"lo" required:"true"  description:"Interface to use. Only supports Ethernet type packets interfaces. Do not use it on SPANs"`
	Bpf            string         `long:"bpf"             short:"f"    default:""   required:"false" description:"tcpdump-style BPF filter"`
	Verbosity      uint8          `long:"verbosity"       short:"v"    default:"1"  required:"false" description:"Verbosity of the metadata: 0 - only pid, 1 - pid and cmd, 2 - pid, cmd and args"`
	ListInterfaces bool           `long:"list-interfaces" short:"l"                 required:"false" description:"List available interfaces and exit"`
	LuaDissector   bool           `long:"lua-dissector"   short:"d"                 required:"false" description:"Print the Lua dissector used in Wireshark"`
}

func main() {
	// todo: embed lua and spit it out
	parser := flags.NewNamedParser("tcpshark", flags.PassDoubleDash|flags.PrintErrors|flags.HelpFlag)
	parser.AddGroup("tcpshark", "tcpshark Options", &GeneralOptions)
	_, err := parser.Parse()

	if GeneralOptions.ListInterfaces {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
		s, err := json.MarshalIndent(ifaces, "", "  ")
		if err != nil {
			log.Fatal().Msg(err.Error())
		}
		fmt.Println("Use the Name attribute of each interface in the --interface flag")
		fmt.Println(string(s))
		os.Exit(0)
	}

	if GeneralOptions.LuaDissector {
		fmt.Println(tcpsharkLua)
		os.Exit(0)
	}

	if err != nil {
		os.Exit(-1)
	}

	handleInterrupt()

	// reload the process lookup table every second
	go func() {
		for range time.Tick(time.Second) {
			plookup := make(map[PacketMetaDataKey]PacketMetaData)
			connData, err := netstat.TCPSocks(netstat.NoopFilter)
			if err != nil {
				log.Fatal().Msg(err.Error())
			}
			u, err := netstat.UDPSocks(netstat.NoopFilter)
			if err != nil {
				log.Fatal().Msg(err.Error())
			}
			connData = append(connData, u...)
			for _, c := range connData {
				if c.Process != nil {
					plookup[PacketMetaDataKey{uint16(c.LocalAddr.Port), uint16(c.RemoteAddr.Port)}] = PacketMetaData{
						Magic:   TcpSharkMagic,
						Pid:     uint32(c.Process.Pid),
						CmdLen:  uint8(len(c.Process.Name)),
						Cmd:     c.Process.Name,
						ArgsLen: 0,
						Args:    "",
					}
				}
			}
			log.Info().Msgf("Reloaded process lookup table with %d connections", len(connData))

			GlobalProcessLookup = plookup
		}
	}()

	capture()
}

package netstat

// lsof-executing implementation.

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

const (
	netstatBinary = "netstat"
	lsofBinary    = "lsof"
)

var (
	lsofFields = "cn" // parseLSOF() depends on the order
)

var skStates = [...]string{
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"", // CLOSE
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

// parseLsof parses lsof out with `-F cn` argument.
//
// Format description: the first letter is the type of record, records are
// newline seperated, the record starting with 'p' (pid) is a new processid.
// There can be multiple connections for the same 'p' record in which case the
// 'p' is not repeated.
//
// For example, this is one process with two listens and one connection:
//
//   p13100
//   cmpd
//   n[::1]:6600
//   n127.0.0.1:6600
//   n[::1]:6600->[::1]:50992
//
func parseLSOF(out string) (map[string]Process, error) {
	var (
		res = map[string]Process{} // Local addr -> Proc
		cp  = Process{}
	)
	for _, line := range strings.Split(out, "\n") {
		if len(line) <= 1 {
			continue
		}

		var (
			field = line[0]
			value = line[1:]
		)
		switch field {
		case 'p':
			pid, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid 'p' field in lsof output: %#v", value)
			}
			cp.Pid = pid

		case 'n':
			// 'n' is the last field, with '-F cn'
			// format examples:
			// "192.168.2.111:44013->54.229.241.196:80"
			// "[2003:45:2b57:8900:1869:2947:f942:aba7]:55711->[2a00:1450:4008:c01::11]:443"
			// "*:111" <- a listen
			addresses := strings.SplitN(value, "->", 2)
			if len(addresses) != 2 {
				// That's a listen entry.
				continue
			}
			res[addresses[0]] = Process{
				Name: cp.Name,
				Pid:  cp.Pid,
			}

		case 'c':
			cp.Name = value

		case 'f':
			continue

		default:
			return nil, fmt.Errorf("unexpected lsof field: %c in %#v", field, value)
		}
	}

	return res, nil
}

// parseDarwinNetstat parses netstat output. (Linux has ip:port, darwin
// ip.port. The 'Proto' column value also differs.)
func parseDarwinNetstat(out string) []SockTabEntry {
	//
	//  Active Internet connections
	//  Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
	//  tcp4       0      0  10.0.1.6.58287         1.2.3.4.443      		ESTABLISHED
	//
	res := []SockTabEntry{}
	for i, line := range strings.Split(out, "\n") {
		if i == 0 || i == 1 {
			// Skip header
			continue
		}

		// Fields are:
		fields := strings.Fields(line)
		if len(fields) != 6 {
			continue
		}

		if fields[5] != "ESTABLISHED" {
			continue
		}

		t := SockTabEntry{
			ino: "tcp",
		}

		// Format is <ip>.<port>
		locals := strings.Split(fields[3], ".")
		if len(locals) < 2 {
			continue
		}

		var (
			localAddress = strings.Join(locals[:len(locals)-1], ".")
			localPort    = locals[len(locals)-1]
		)
		p, err := strconv.Atoi(localPort)
		if err != nil {
			return nil
		}

		t.LocalAddr = &SockAddr{net.ParseIP(localAddress), uint16(p)}

		remotes := strings.Split(fields[4], ".")
		if len(remotes) < 2 {
			continue
		}

		var (
			remoteAddress = strings.Join(remotes[:len(remotes)-1], ".")
			remotePort    = remotes[len(remotes)-1]
		)
		p, err = strconv.Atoi(remotePort)
		if err != nil {
			return nil
		}
		t.RemoteAddr = &SockAddr{net.ParseIP(remoteAddress), uint16(p)}

		res = append(res, t)
	}

	return res
}

// Connections returns all established (TCP) connections. No need to be root
// to run this. If processes is true it also tries to fill in the process
// fields of the connection. You need to be root to find all processes.
func osTCPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	out, err := exec.Command(
		netstatBinary,
		"-n", // no number resolving
		"-W", // Wide output
		// "-l", // full IPv6 addresses // What does this do?
		"-p", "tcp", // only TCP
	).CombinedOutput()
	if err != nil {
		// log.Printf("lsof error: %s", err)
		return nil, err
	}
	connections := parseDarwinNetstat(string(out))

	out, err = exec.Command(
		lsofBinary,
		"-i",       // only Internet files
		"-n", "-P", // no number resolving
		"-w",             // no warnings
		"-F", lsofFields, // \n based output of only the fields we want.
	).CombinedOutput()
	if err != nil {
		return nil, err
	}

	procs, err := parseLSOF(string(out))
	if err != nil {
		return nil, err
	}
	for local, proc := range procs {
		for i, c := range connections {
			localAddr := c.LocalAddr.String()
			if localAddr == local {
				connections[i].Process = &proc
			}
		}

	}

	return connections, nil
}

func osTCP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return []SockTabEntry{}, nil
}

func osUDPSocks(accept AcceptFn) ([]SockTabEntry, error) {
	return []SockTabEntry{}, nil
}

func osUDP6Socks(accept AcceptFn) ([]SockTabEntry, error) {
	return []SockTabEntry{}, nil
}

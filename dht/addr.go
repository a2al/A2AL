package dht

import (
	"encoding/binary"
	"net"

	"github.com/a2al/a2al"
	"github.com/a2al/a2al/protocol"
)

// ObservedAddr encodes remote IP:port for PONG / FIND_*_RESP (spec §7.6).
func ObservedAddr(from net.Addr) []byte {
	switch a := from.(type) {
	case *net.UDPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			out := make([]byte, 0, 6)
			out = append(out, ip4...)
			return binary.BigEndian.AppendUint16(out, uint16(a.Port))
		}
		ip16 := a.IP.To16()
		out := make([]byte, 0, 18)
		out = append(out, ip16...)
		return binary.BigEndian.AppendUint16(out, uint16(a.Port))
	default:
		// Mem transport and other logical addrs: placeholder loopback.
		out := net.IPv4(127, 0, 0, 1).To4()
		return append(append([]byte(nil), out...), 0, 0)
	}
}

func nodeIDKey(id a2al.NodeID) string {
	return string(id[:])
}

func nodeInfoFromMessage(dec *protocol.DecodedMessage, from net.Addr) protocol.NodeInfo {
	nid := a2al.NodeIDFromAddress(dec.SenderAddr)
	ni := protocol.NodeInfo{
		Address: append([]byte(nil), dec.SenderAddr[:]...),
		NodeID:  append([]byte(nil), nid[:]...),
	}
	switch a := from.(type) {
	case *net.UDPAddr:
		if ip4 := a.IP.To4(); ip4 != nil {
			ni.IP = append([]byte(nil), ip4...)
		} else {
			ni.IP = append([]byte(nil), a.IP.To16()...)
		}
		ni.Port = uint16(a.Port)
	default:
		ni.IP = net.IPv4(127, 0, 0, 1).To4()
		ni.Port = 0
	}
	return ni
}

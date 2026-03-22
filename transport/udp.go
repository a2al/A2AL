package transport

import "net"

// UDPTransport wraps a UDP socket with a max read size (spec §3.7).
type UDPTransport struct {
	conn *net.UDPConn
}

// ListenUDP listens on laddr (e.g. "udp4", ":0") and returns a UDPTransport.
func ListenUDP(network, laddr string) (*UDPTransport, error) {
	a, err := net.ResolveUDPAddr(network, laddr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP(network, a)
	if err != nil {
		return nil, err
	}
	return &UDPTransport{conn: c}, nil
}

// NewUDPTransport wraps an existing UDP connection.
func NewUDPTransport(c *net.UDPConn) *UDPTransport {
	return &UDPTransport{conn: c}
}

func (t *UDPTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

func (t *UDPTransport) Send(addr net.Addr, data []byte) error {
	if len(data) > MaxPacketSize {
		return ErrPacketTooLarge
	}
	_, err := t.conn.WriteTo(data, addr)
	return err
}

func (t *UDPTransport) Receive() ([]byte, net.Addr, error) {
	buf := make([]byte, MaxPacketSize)
	n, addr, err := t.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	out := make([]byte, n)
	copy(out, buf[:n])
	return out, addr, nil
}

func (t *UDPTransport) Close() error {
	return t.conn.Close()
}

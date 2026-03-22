package transport

var (
	_ Transport = (*MemTransport)(nil)
	_ Transport = (*UDPTransport)(nil)
)

package packet_setting

import (
	"net"
)

// TODO: how to make this prettier?
// define an interface with the needed methods to avoid import cycle
type QuicConnection interface {

	// LocalAddr returns the local address.
	LocalAddr() net.Addr
	// RemoteAddr returns the address of the peer.
	RemoteAddr() net.Addr

	// PRIO_PACKS_TAG
	// get the priority of a corresponding stream using the streamID
	// GetStreamPriority(StreamID) StreamPriority

	// PACKET_NUMBER_TAG
	// SetPacketNumber sets the packet number for the next packet sent on the connection.
	// This is needed if bpf porgrams are sending packets.
	SetPacketNumber(int64)
	// SetHighestSent sets the highest packet number sent on the connection.
	// This is needed if bpf porgrams are sending packets.
	SetHighestSent(int64)
	// (Un-)Locking the packet number setting so that it is not changed during actively checking
	// a packet number of a packet.
	Lock()
	Unlock()
}

var (
	ALLOW_SETTING_PN                bool                                          = false
	OMIT_CONN_ID_RETIREMENT         bool                                          = false
	ConnectionRetirementBPFHandler  func(id []byte, l uint8, conn QuicConnection) = nil
	ConnectionInitiationBPFHandler  func(id []byte, l uint8, conn QuicConnection) = nil
	ConnectionUpdateBPFHandler      func(id []byte, l uint8, conn QuicConnection) = nil
	PacketNumberIncrementBPFHandler func(pn int64, conn QuicConnection)           = nil
)

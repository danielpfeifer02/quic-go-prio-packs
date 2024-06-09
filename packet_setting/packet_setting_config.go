package packet_setting

import (
	"net"
	"sync"
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
	// GetPriority(StreamID) Priority

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

type Range struct {
	Smallest int64
	Largest  int64
}

// BPF_CC_TAG
type PacketRegisterContainerBPF struct {
	// The packet number of the packet
	PacketNumber int64
	SentTime     int64
	Length       int64
}

var (
	ALLOW_SETTING_PN                bool                                          = false
	OMIT_CONN_ID_RETIREMENT         bool                                          = false
	SET_ONLY_APP_DATA               bool                                          = true
	PRINT_PACKET_RECEIVING_INFO     bool                                          = false
	ConnectionRetirementBPFHandler  func(id []byte, l uint8, conn QuicConnection) = nil
	ConnectionInitiationBPFHandler  func(id []byte, l uint8, conn QuicConnection) = nil
	ConnectionUpdateBPFHandler      func(id []byte, l uint8, conn QuicConnection) = nil
	PacketNumberIncrementBPFHandler func(pn int64, conn QuicConnection)           = nil

	// get the largest sent packet number of a connection
	ConnectionGetLargestSentPacketNumber func(conn QuicConnection) int64 = nil

	// Important note: this function should return "pn, err" in case of an error
	AckTranslationBPFHandler         func(pn int64, conn QuicConnection) (int64, error) = nil
	AckTranslationDeletionBPFHandler func(pn int64, conn QuicConnection)                = nil
	// CheckIfAckShouldBeIgnored func(pn int64, conn QuicConnection) bool           = nil // TODO: remove

	SERVER_ADDR    string = "192.168.10.1:4242"
	RELAY_ADDR     string = "192.168.11.2:4242"
	RELAY_OOB_ADDR string = "192.168.11.2:12345"
	IS_CLIENT      bool   = false
	EXCHANGE_PRIOS bool   = true

	RangeTranslationMap             map[Range]Range = make(map[Range]Range)
	IndividualAckTranslationMap     map[int64]int64 = make(map[int64]int64)
	IndividualAckTranslationMapLock sync.Mutex      = sync.Mutex{}

	// BPF_CC_TAG
	BPF_PACKET_REGISTRATION bool = false

	ReceivedPacketAtTimestampHandler func(pn, ts int64, conn QuicConnection) = nil
)

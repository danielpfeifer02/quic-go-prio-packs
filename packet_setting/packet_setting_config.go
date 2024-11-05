package packet_setting

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
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
	Offset       int64

	RawData []byte

	Frames       []GeneralFrame
	StreamFrames []StreamFrame
}

type RetransmissionPacketContainer struct {
	PacketNumber int64
	Length       int64
	Timestamp    int64
	RawData      []byte
	Valid        bool
}

type StreamFrame struct {
	StreamID       protocol.StreamID
	Offset         protocol.ByteCount
	Data           []byte
	Fin            bool
	DataLenPresent bool
}

type GeneralFrame struct {
}

type CongestionWindowData struct {
	MinRTT      time.Duration
	SmoothedRTT time.Duration
	LatestRTT   time.Duration
	RTTVariance time.Duration

	CongestionWindow protocol.ByteCount
	BytesInFlight    protocol.ByteCount
	PacketsInFlight  int
}

type PacketNumberMapping struct {
	OriginalPacketNumber int64
	NewPacketNumber      int64
}

type PacketIdentifierStruct struct {
	PacketNumber    uint64
	StreamID        uint64
	ConnectionID    []uint8
	ConnectionIDLen uint8
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

	// RETRANSMISSION_TAG
	// STREAM_ID_TAG
	MarkStreamIdAsRetransmission func(stream_id uint64, conn QuicConnection) = nil
	MarkPacketAsRetransmission   func(PacketIdentifierStruct)                = nil

	// BPF_CC_TAG
	// CONGESTION_WINDOW_TAG
	HandleCongestionMetricUpdate func(data CongestionWindowData, conn QuicConnection) = nil

	// RETRANSMISSON_TAG
	StoreServerPacket                           func(pn, ts int64, data []byte, conn QuicConnection)                  = nil
	RemoveServerPacket                          func(pn int64, conn QuicConnection)                                   = nil
	StoreRelayPacket                            func(pn, ts int64, data []byte, conn QuicConnection)                  = nil
	RemoveRelayPacket                           func(pn int64, conn QuicConnection)                                   = nil
	GetRetransmitServerPacketAfterPNTranslation func(bpf_pn int64, conn QuicConnection) RetransmissionPacketContainer = nil

	// get the largest sent packet number of a connection
	ConnectionGetLargestSentPacketNumber func(conn QuicConnection) int64 = nil

	// Important note: this function should return "pn, err" in case of an error
	AckTranslationBPFHandler         func(pn int64, conn QuicConnection) (int64, error) = nil
	AckTranslationDeletionBPFHandler func(pn int64, conn QuicConnection)                = nil

	SERVER_ADDR    string = "192.168.10.1:4242"
	RELAY_ADDR     string = "192.168.11.2:4242"
	RELAY_OOB_ADDR string = "192.168.11.2:12345"
	IS_CLIENT      bool   = false
	IS_RELAY       bool   = false
	EXCHANGE_PRIOS bool   = false // TODO: what's the smarter default value?
	BPF_TURNED_ON  bool   = true

	RangeTranslationMap             map[Range]Range = make(map[Range]Range)
	IndividualAckTranslationMap     map[int64]int64 = make(map[int64]int64)
	IndividualAckTranslationMapLock sync.Mutex      = sync.Mutex{}

	// BPF_CC_TAG
	BPF_PACKET_REGISTRATION bool = false

	BPF_PACKET_RETRANSMISSION bool = true

	RELAY_CWND_DATA_PRINT bool = true

	ReceivedPacketAtTimestampHandler func(pn, ts int64, conn QuicConnection) = nil

	RetransmissionStreamMap map[protocol.StreamID]interface{} = make(map[protocol.StreamID]interface{})

	RetransmissionPacketNumberTranslationHandler func(old_pn, new_pn int64, conn QuicConnection) = nil

	DEBUG_PRINT bool = false

	AckedCache     map[int64]bool = make(map[int64]bool)
	AckedCacheLock sync.Mutex     = sync.Mutex{}

	PacketOriginatedAtRelay func(pn int64) bool = nil

	VALID_FLAG          uint32 = 1 << 0
	USERSPACE_FLAG      uint32 = 1 << 1
	RETRANSMISSION_FLAG uint32 = 1 << 2
)

func DebugPrintln(s ...any) {
	if DEBUG_PRINT {
		fmt.Println(s...)
	}
}

func RetransmitDebug(data []byte) {
	l := len(data)
	b := data[l-1] == 0x69 && data[l-2] == 0x69 && data[l-3] == 0x69
	if b {
		fmt.Println("retransmit debug")
	}
}

package priority_setting

import "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"

var (
	NoPriority   protocol.StreamPriority = -1
	LowPriority  protocol.StreamPriority = 0
	HighPriority protocol.StreamPriority = 1
)

// PRIO_PACKS_TAG
// TODOME: maybe add possibility of more specifc prio handling
// e.g. for different packet types
var (
	PrioRetryPacket           protocol.StreamPriority = 1
	PrioConnectionClosePacket protocol.StreamPriority = 1
	PrioCoalescedPacket       protocol.StreamPriority = 1
	PrioAppendPacket          protocol.StreamPriority = 1
	PrioProbePacket           protocol.StreamPriority = 1
	PrioMTUProbePacket        protocol.StreamPriority = 1
	PrioLongHeaderPacket      protocol.StreamPriority = 1
)

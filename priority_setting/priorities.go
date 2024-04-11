package priority_setting

import "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"

var (
	NoPriority   protocol.Priority = -1
	LowPriority  protocol.Priority = 0
	HighPriority protocol.Priority = 1
)

// PRIO_PACKS_TAG
// TODOME: maybe add possibility of more specifc prio handling
// e.g. for different packet types
var (
	PrioRetryPacket           protocol.Priority = 1
	PrioConnectionClosePacket protocol.Priority = 1
	PrioCoalescedPacket       protocol.Priority = 1
	PrioAppendPacket          protocol.Priority = 1
	PrioProbePacket           protocol.Priority = 1
	PrioMTUProbePacket        protocol.Priority = 1
	PrioLongHeaderPacket      protocol.Priority = 1
)

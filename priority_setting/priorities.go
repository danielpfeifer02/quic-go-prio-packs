package priority_setting

import "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"

var (
	// TODO: NoPriority equal to zero so that empty structs that don't init a prio automatically get no priority?
	NoPriority   protocol.Priority = 0
	LowPriority  protocol.Priority = 1
	HighPriority protocol.Priority = 2

	LowestPriority     int8 = int8(LowPriority)
	NumberOfPriorities int  = 2
)

// PRIO_PACKS_TAG
// TODOME: maybe add possibility of more specifc prio handling
// e.g. for different packet types
var (
	PrioRetryPacket           protocol.Priority = HighPriority
	PrioConnectionClosePacket protocol.Priority = HighPriority
	PrioCoalescedPacket       protocol.Priority = HighPriority
	PrioAppendPacket          protocol.Priority = HighPriority
	PrioProbePacket           protocol.Priority = HighPriority
	PrioMTUProbePacket        protocol.Priority = HighPriority
	PrioLongHeaderPacket      protocol.Priority = HighPriority
)

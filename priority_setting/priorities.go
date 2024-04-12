package priority_setting

import "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"

type Priority protocol.Priority

var (
	// TODO: NoPriority equal to zero so that empty structs that don't init a prio automatically get no priority?
	NoPriority   Priority = 0
	LowPriority  Priority = 1
	HighPriority Priority = 2

	LowestPriority     int8 = int8(LowPriority)
	NumberOfPriorities int  = 2
)

// PRIO_PACKS_TAG
// TODOME: maybe add possibility of more specifc prio handling
// e.g. for different packet types
var (
	PrioRetryPacket           Priority = HighPriority
	PrioConnectionClosePacket Priority = HighPriority
	PrioCoalescedPacket       Priority = HighPriority
	PrioAppendPacket          Priority = HighPriority
	PrioProbePacket           Priority = HighPriority
	PrioMTUProbePacket        Priority = HighPriority
	PrioLongHeaderPacket      Priority = HighPriority
)

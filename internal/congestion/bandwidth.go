package congestion

import (
	"math"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
)

// Bandwidth of a connection
type Bandwidth uint64

const infBandwidth Bandwidth = math.MaxUint64

const (
	// BitsPerSecond is 1 bit per second
	BitsPerSecond Bandwidth = 1
	// BytesPerSecond is 1 byte per second
	BytesPerSecond = 8 * BitsPerSecond
)

// BandwidthFromDelta calculates the bandwidth from a number of bytes and a time delta
func BandwidthFromDelta(bytes protocol.ByteCount, delta time.Duration) Bandwidth {
	// //fmt.Println("BandwidthFromDelta", bytes, delta)
	return Bandwidth(bytes) * Bandwidth(time.Second) / Bandwidth(delta) * BytesPerSecond
}

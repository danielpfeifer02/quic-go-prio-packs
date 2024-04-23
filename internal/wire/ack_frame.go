package wire

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/utils"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/quicvarint"
)

var errInvalidAckRanges = errors.New("AckFrame: ACK frame contains invalid ACK ranges")

// An AckFrame is an ACK frame
type AckFrame struct {
	AckRanges []AckRange // has to be ordered. The highest ACK range goes first, the lowest ACK range goes last
	DelayTime time.Duration

	ECT0, ECT1, ECNCE uint64
}

// parseAckFrame reads an ACK frame
func parseAckFrame(frame *AckFrame, r *bytes.Reader, typ uint64, ackDelayExponent uint8, _ protocol.Version) error {
	ecn := typ == ackECNFrameType

	la, err := quicvarint.Read(r)
	if err != nil {
		return err
	}
	largestAcked := protocol.PacketNumber(la)
	delay, err := quicvarint.Read(r)
	if err != nil {
		return err
	}

	delayTime := time.Duration(delay*1<<ackDelayExponent) * time.Microsecond
	if delayTime < 0 {
		// If the delay time overflows, set it to the maximum encode-able value.
		delayTime = utils.InfDuration
	}
	frame.DelayTime = delayTime

	numBlocks, err := quicvarint.Read(r)
	if err != nil {
		return err
	}

	// read the first ACK range
	ab, err := quicvarint.Read(r)
	if err != nil {
		return err
	}
	ackBlock := protocol.PacketNumber(ab)
	if ackBlock > largestAcked {
		return errors.New("invalid first ACK range")
	}
	smallest := largestAcked - ackBlock
	frame.AckRanges = append(frame.AckRanges, AckRange{Smallest: smallest, Largest: largestAcked})

	// read all the other ACK ranges
	for i := uint64(0); i < numBlocks; i++ {
		g, err := quicvarint.Read(r)
		if err != nil {
			return err
		}
		gap := protocol.PacketNumber(g)
		if smallest < gap+2 {
			return errInvalidAckRanges
		}
		largest := smallest - gap - 2

		ab, err := quicvarint.Read(r)
		if err != nil {
			return err
		}
		ackBlock := protocol.PacketNumber(ab)

		if ackBlock > largest {
			return errInvalidAckRanges
		}
		smallest = largest - ackBlock
		frame.AckRanges = append(frame.AckRanges, AckRange{Smallest: smallest, Largest: largest})
	}

	if !frame.validateAckRanges() {
		return errInvalidAckRanges
	}

	if ecn {
		ect0, err := quicvarint.Read(r)
		if err != nil {
			return err
		}
		frame.ECT0 = ect0
		ect1, err := quicvarint.Read(r)
		if err != nil {
			return err
		}
		frame.ECT1 = ect1
		ecnce, err := quicvarint.Read(r)
		if err != nil {
			return err
		}
		frame.ECNCE = ecnce
	}

	return nil
}

// Append appends an ACK frame.
func (f *AckFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	hasECN := f.ECT0 > 0 || f.ECT1 > 0 || f.ECNCE > 0
	if hasECN {
		b = append(b, ackECNFrameType)
	} else {
		b = append(b, ackFrameType)
	}
	b = quicvarint.Append(b, uint64(f.LargestAcked()))
	b = quicvarint.Append(b, encodeAckDelay(f.DelayTime))

	numRanges := f.numEncodableAckRanges()
	b = quicvarint.Append(b, uint64(numRanges-1))

	// write the first range
	_, firstRange := f.encodeAckRange(0)
	b = quicvarint.Append(b, firstRange)

	// write all the other range
	for i := 1; i < numRanges; i++ {
		gap, len := f.encodeAckRange(i)
		b = quicvarint.Append(b, gap)
		b = quicvarint.Append(b, len)
	}

	if hasECN {
		b = quicvarint.Append(b, f.ECT0)
		b = quicvarint.Append(b, f.ECT1)
		b = quicvarint.Append(b, f.ECNCE)
	}
	return b, nil
}

// Length of a written frame
func (f *AckFrame) Length(_ protocol.Version) protocol.ByteCount {
	largestAcked := f.AckRanges[0].Largest
	numRanges := f.numEncodableAckRanges()

	length := 1 + quicvarint.Len(uint64(largestAcked)) + quicvarint.Len(encodeAckDelay(f.DelayTime))

	length += quicvarint.Len(uint64(numRanges - 1))
	lowestInFirstRange := f.AckRanges[0].Smallest
	length += quicvarint.Len(uint64(largestAcked - lowestInFirstRange))

	for i := 1; i < numRanges; i++ {
		gap, len := f.encodeAckRange(i)
		length += quicvarint.Len(gap)
		length += quicvarint.Len(len)
	}
	if f.ECT0 > 0 || f.ECT1 > 0 || f.ECNCE > 0 {
		length += quicvarint.Len(f.ECT0)
		length += quicvarint.Len(f.ECT1)
		length += quicvarint.Len(f.ECNCE)
	}
	return length
}

// gets the number of ACK ranges that can be encoded
// such that the resulting frame is smaller than the maximum ACK frame size
func (f *AckFrame) numEncodableAckRanges() int {
	length := 1 + quicvarint.Len(uint64(f.LargestAcked())) + quicvarint.Len(encodeAckDelay(f.DelayTime))
	length += 2 // assume that the number of ranges will consume 2 bytes
	for i := 1; i < len(f.AckRanges); i++ {
		gap, len := f.encodeAckRange(i)
		rangeLen := quicvarint.Len(gap) + quicvarint.Len(len)
		if length+rangeLen > protocol.MaxAckFrameSize {
			// Writing range i would exceed the MaxAckFrameSize.
			// So encode one range less than that.
			return i - 1
		}
		length += rangeLen
	}
	return len(f.AckRanges)
}

func (f *AckFrame) encodeAckRange(i int) (uint64 /* gap */, uint64 /* length */) {
	if i == 0 {
		return 0, uint64(f.AckRanges[0].Largest - f.AckRanges[0].Smallest)
	}
	return uint64(f.AckRanges[i-1].Smallest - f.AckRanges[i].Largest - 2),
		uint64(f.AckRanges[i].Largest - f.AckRanges[i].Smallest)
}

// HasMissingRanges returns if this frame reports any missing packets
func (f *AckFrame) HasMissingRanges() bool {
	return len(f.AckRanges) > 1
}

func (f *AckFrame) validateAckRanges() bool {
	if len(f.AckRanges) == 0 {
		return false
	}

	// check the validity of every single ACK range
	for _, ackRange := range f.AckRanges {
		if ackRange.Smallest > ackRange.Largest {
			return false
		}
	}

	// check the consistency for ACK with multiple NACK ranges
	for i, ackRange := range f.AckRanges {
		if i == 0 {
			continue
		}
		lastAckRange := f.AckRanges[i-1]
		if lastAckRange.Smallest <= ackRange.Smallest {
			return false
		}
		if lastAckRange.Smallest <= ackRange.Largest+1 {
			return false
		}
	}

	return true
}

// LargestAcked is the largest acked packet number
func (f *AckFrame) LargestAcked() protocol.PacketNumber {
	return f.AckRanges[0].Largest
}

// LowestAcked is the lowest acked packet number
func (f *AckFrame) LowestAcked() protocol.PacketNumber {
	return f.AckRanges[len(f.AckRanges)-1].Smallest
}

// AcksPacket determines if this ACK frame acks a certain packet number
func (f *AckFrame) AcksPacket(p protocol.PacketNumber) bool {

	if p < f.LowestAcked() || p > f.LargestAcked() {
		return false
	}

	i := sort.Search(len(f.AckRanges), func(i int) bool {
		return p >= f.AckRanges[i].Smallest
	})
	// i will always be < len(f.AckRanges), since we checked above that p is not bigger than the largest acked
	return p <= f.AckRanges[i].Largest
}

func (f *AckFrame) Reset() {
	f.DelayTime = 0
	f.ECT0 = 0
	f.ECT1 = 0
	f.ECNCE = 0
	for _, r := range f.AckRanges {
		r.Largest = 0
		r.Smallest = 0
	}
	f.AckRanges = f.AckRanges[:0]
}

func encodeAckDelay(delay time.Duration) uint64 {
	return uint64(delay.Nanoseconds() / (1000 * (1 << protocol.AckDelayExponent)))
}

// BPF_MAP_TAG
func (f *AckFrame) UpdateAckRanges(conn packet_setting.QuicConnection) { // TODONOW: fix this

	// This rules out that the Acks are changed at server or client side
	// in the example
	if packet_setting.AckTranslationBPFHandler == nil {
		return
	}
	if conn.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		return
	}

	removable_indices := make([]int, 0)

	// fmt.Println()

	for i := 0; i < len(f.AckRanges); i++ { // TODONOW: AckRanges are only the ranges of ACKed pns without the gaps right?

		fmt.Println("Range ", i, " Smallest: ", f.AckRanges[i].Smallest, " Largest: ", f.AckRanges[i].Largest)

		smallest := f.AckRanges[i].Smallest
		largest := f.AckRanges[i].Largest

		// check range translation map
		// if translated range is in the map, use it
		// if translated range is not in the map, translate it
		if packet_setting.RangeTranslationMap != nil {
			if translated_range,
				ok := packet_setting.RangeTranslationMap[packet_setting.Range{Smallest: int64(smallest), Largest: int64(largest)}]; ok {
				f.AckRanges[i].Smallest = protocol.PacketNumber(translated_range.Smallest)
				f.AckRanges[i].Largest = protocol.PacketNumber(translated_range.Largest)
				continue
			}
		}

		var new_smallest, new_largest int64
		var err error
		for j := smallest; j <= largest; j++ {
			// fmt.Println("Trying to translate: ", smallest) // TODO: output seems wrong
			new_smallest, err = packet_setting.AckTranslationBPFHandler(int64(j), conn)
			if err == nil {
				break
			}
		}
		if err != nil {
			fmt.Println("Whole range empty")
			removable_indices = append(removable_indices, i)
			continue
		}
		f.AckRanges[i].Smallest = protocol.PacketNumber(new_smallest)

		for j := largest; j >= smallest; j-- {
			new_largest, err = packet_setting.AckTranslationBPFHandler(int64(j), conn)
			if err == nil {
				break
			}
		}
		if err == nil {
			f.AckRanges[i].Largest = protocol.PacketNumber(new_largest)
		}

		// update range translation map
		if packet_setting.RangeTranslationMap != nil {
			packet_setting.RangeTranslationMap[packet_setting.Range{Smallest: int64(smallest), Largest: int64(largest)}] =
				packet_setting.Range{Smallest: new_smallest, Largest: new_largest}
		}

	}

	for i := len(removable_indices) - 1; i >= 0; i-- {
		f.AckRanges = append(f.AckRanges[:removable_indices[i]], f.AckRanges[removable_indices[i]+1:]...)
	}

	go func(f *AckFrame, conn packet_setting.QuicConnection) {
		if packet_setting.AckTranslationDeletionBPFHandler != nil {
			// It is fine here to use the already trimmed ranges
			// since we never remove any pn that can be translated
			// from the range but only ones that are not translatable
			// i.e. sent from the bpf program
			for i := 0; i < len(f.AckRanges); i++ {
				smallest := f.AckRanges[i].Smallest
				largest := f.AckRanges[i].Largest
				for j := smallest; j < largest+1; j++ {
					fmt.Println("Deleting: ", j)
					packet_setting.AckTranslationDeletionBPFHandler(int64(j), conn)
				}
			}
		}
	}(f, conn)

}

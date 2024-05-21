package ackhandler

import (
	"fmt"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

type sentPacketHistory struct {
	packets []*packet

	numOutstanding int

	highestPacketNumber protocol.PacketNumber

	// BPF_CC_TAG // TODO: clean up whats not needed
	updateLargestSent func(pn protocol.PacketNumber)
	largestSent       protocol.PacketNumber
}

func newSentPacketHistory() *sentPacketHistory {
	return &sentPacketHistory{
		packets:             make([]*packet, 0, 32),
		highestPacketNumber: protocol.InvalidPacketNumber,
		largestSent:         protocol.InvalidPacketNumber,
	}
}

func (h *sentPacketHistory) checkSequentialPacketNumberUse(pn protocol.PacketNumber) {

	// PACKET_NUMBER_TAG
	// BPF_CC_TAG
	if packet_setting.ALLOW_SETTING_PN ||
		packet_setting.BPF_PACKET_REGISTRATION {
		return
	}

	if h.highestPacketNumber != protocol.InvalidPacketNumber {
		if pn != h.highestPacketNumber+1 {
			panic("non-sequential packet number use")
		}
	}
}

func (h *sentPacketHistory) SkippedPacket(pn protocol.PacketNumber) {
	h.checkSequentialPacketNumberUse(pn)
	h.highestPacketNumber = pn
	h.packets = append(h.packets, &packet{
		PacketNumber:  pn,
		skippedPacket: true,
	})
}

func (h *sentPacketHistory) SentNonAckElicitingPacket(pn protocol.PacketNumber) {
	h.checkSequentialPacketNumberUse(pn)
	h.highestPacketNumber = pn
	if len(h.packets) > 0 {
		h.packets = append(h.packets, nil)
	}
}

func (h *sentPacketHistory) SentAckElicitingPacket(p *packet) {
	h.checkSequentialPacketNumberUse(p.PacketNumber)
	h.highestPacketNumber = p.PacketNumber
	h.packets = append(h.packets, p)
	if p.outstanding() {
		h.numOutstanding++
	}
}

// BPF_CC_TAG
func (h *sentPacketHistory) SentBPFPacket(prc packet_setting.PacketRegisterContainerBPF, pns *packetNumberSpace) {
	// TODONOW: what is needed here?
	pn := protocol.PacketNumber(prc.PacketNumber)
	tm := time.Unix(0, prc.SentTime)
	le := protocol.ByteCount(prc.Length)

	// We also need to update the largest sent packet number
	// from the sent_packet_handler
	if pn > pns.largestSent {
		pns.largestSent = pn
	}

	// We do not check for sequential packet number use for BPF packets
	// since those could be "registered" out of order. (TODONOW: i think?)

	bpf_packet := &packet{ // TODO: what fields should be set here?
		SendTime:        tm,
		PacketNumber:    pn,
		StreamFrames:    nil,
		Frames:          nil,
		LargestAcked:    protocol.InvalidPacketNumber,
		Length:          le,
		EncryptionLevel: protocol.Encryption0RTT,
	}

	// Insert the BPF packet at the correct position
	// (i.e., the position of the first packet with a higher packet number)
	// lock := &sync.Mutex{}
	for i, p := range h.packets {
		// go func(p *packet, i int, lock *sync.Mutex) {
		if p == nil || p.PacketNumber > pn {
			h.packets = append(h.packets[:i], append([]*packet{bpf_packet}, h.packets[i:]...)...)

			h.numOutstanding++

			if pn > h.highestPacketNumber {
				h.highestPacketNumber = pn
			}

			return

		}
		// }(p, i, lock) // TODONOW: use go routine with lock?
	}
}

// Iterate iterates through all packets.
func (h *sentPacketHistory) Iterate(cb func(*packet) (cont bool, err error)) error {
	for _, p := range h.packets {
		if p == nil {
			continue
		}
		cont, err := cb(p)
		if err != nil {
			return err
		}
		if !cont {
			return nil
		}
	}
	return nil
}

// FirstOutstanding returns the first outstanding packet.
func (h *sentPacketHistory) FirstOutstanding() *packet {
	if !h.HasOutstandingPackets() {
		return nil
	}
	for _, p := range h.packets {
		if p != nil && p.outstanding() {
			return p
		}
	}
	return nil
}

func (h *sentPacketHistory) Len() int {
	return len(h.packets)
}

func (h *sentPacketHistory) Remove(pn protocol.PacketNumber) error {
	idx, ok := h.getIndex(pn)
	if !ok { // Potentially we have to wait until the packet is registered

		// BPF_CC_TAG
		if packet_setting.BPF_PACKET_REGISTRATION {
			max_iterations := 100
			for i := 0; i < max_iterations; i++ {
				idx, ok = h.getIndex(pn)
				if ok {
					break
				}
				time.Sleep(1 * time.Millisecond)
			}
			if !ok {
				return fmt.Errorf("packet %d not found in sent packet history", pn)
			}
		} else {
			return fmt.Errorf("packet %d not found in sent packet history", pn)
		}
	}
	p := h.packets[idx]
	if p.outstanding() {
		h.numOutstanding--
		if h.numOutstanding < 0 {
			panic("negative number of outstanding packets")
		}
	}
	h.packets[idx] = nil
	// clean up all skipped packets directly before this packet number
	for idx > 0 {
		idx--
		p := h.packets[idx]
		if p == nil || !p.skippedPacket {
			break
		}
		h.packets[idx] = nil
	}
	if idx == 0 {
		h.cleanupStart()
	}
	if len(h.packets) > 0 && h.packets[0] == nil {
		panic("remove failed")
	}
	return nil
}

// getIndex gets the index of packet p in the packets slice.
func (h *sentPacketHistory) getIndex(p protocol.PacketNumber) (int, bool) {

	if len(h.packets) > 0 && h.packets[0] == nil {
		h.cleanupStart()
	}
	if len(h.packets) == 0 {
		return 0, false
	}

	first := h.packets[0].PacketNumber
	if p < first {
		return 0, false
	}

	// BPF_CC_TAG
	// In case the packet registering is on we cannot be sure that
	// all packets are already registered.
	// Therefore a little more complex search is needed.
	if packet_setting.BPF_PACKET_REGISTRATION {

		// TODONOW: turn into algo with better complexity
		for i, pack := range h.packets {
			if pack == nil {
				continue
			}
			if pack.PacketNumber == p {
				return i, true
			}
		}
		return 0, false

		// // Do binary search for the index and return 0, false if
		// // the index is not found
		// low := 0
		// high := len(h.packets) - 1
		// for low <= high {
		// 	mid := (low + high) / 2
		// 	if h.packets[mid].PacketNumber == p {
		// 		return mid, true
		// 	}
		// 	if h.packets[mid].PacketNumber < p {
		// 		low = mid + 1
		// 	} else {
		// 		high = mid - 1
		// 	}
		// }
		// return 0, false

	}

	index := int(p - first)
	if index > len(h.packets)-1 {
		return 0, false
	}
	return index, true
}

func (h *sentPacketHistory) HasOutstandingPackets() bool {
	return h.numOutstanding > 0
}

// delete all nil entries at the beginning of the packets slice
func (h *sentPacketHistory) cleanupStart() {
	for i, p := range h.packets {
		if p != nil {
			h.packets = h.packets[i:]
			return
		}
	}
	h.packets = h.packets[:0]
}

func (h *sentPacketHistory) LowestPacketNumber() protocol.PacketNumber {
	if len(h.packets) == 0 {
		return protocol.InvalidPacketNumber
	}
	return h.packets[0].PacketNumber
}

func (h *sentPacketHistory) DeclareLost(pn protocol.PacketNumber) {
	idx, ok := h.getIndex(pn)
	if !ok {
		return
	}
	p := h.packets[idx]
	if p.outstanding() {
		h.numOutstanding--
		if h.numOutstanding < 0 {
			panic("negative number of outstanding packets")
		}
	}
	h.packets[idx] = nil
	if idx == 0 {
		h.cleanupStart()
	}
}

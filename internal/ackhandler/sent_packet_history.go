package ackhandler

import (
	"fmt"
	"sync"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
)

type sentPacketHistory struct {
	packets []*packet

	numOutstanding int

	highestPacketNumber protocol.PacketNumber

	largestSent protocol.PacketNumber

	// DEBUG_TAG
	translation_map map[protocol.PacketNumber]protocol.PacketNumber

	insertionMutex *sync.Mutex
}

func newSentPacketHistory() *sentPacketHistory {
	return &sentPacketHistory{
		packets:             make([]*packet, 0, 32),
		highestPacketNumber: protocol.InvalidPacketNumber,
		largestSent:         protocol.InvalidPacketNumber,
		insertionMutex:      &sync.Mutex{},
		// DEBUG_TAG
		translation_map: make(map[protocol.PacketNumber]protocol.PacketNumber),
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

// DEBUG_TAG
func (h *sentPacketHistory) SentBPFPacket(p_in *packet) {

	if p_in.PacketNumber > h.highestPacketNumber {
		h.highestPacketNumber = p_in.PacketNumber
	}
	// Insert the BPF packet at the correct position
	// (i.e., the position of the first packet with a higher packet number)
	// lock := &sync.Mutex{}

	p_in.SendTime = time.Now()
	p_in.IsBPFRegisteredPacket = true

	pn := p_in.PacketNumber
	for i := 0; i <= len(h.packets); i++ {
		var p *packet
		if i == len(h.packets) {
			p = nil
		} else {
			p = h.packets[i]
		}
		// TODO: would a go routine here cause better performance?
		if p == nil || p.PacketNumber > pn {
			h.packets = append(h.packets[:i], append([]*packet{p_in}, h.packets[i:]...)...)

			if p_in.outstanding() {
				h.numOutstanding++
			}

			if pn > h.highestPacketNumber {
				h.highestPacketNumber = pn
			}
			return

		}
	}
	panic("This should not happen (BPF packet insertion failed)")
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

// BPF_RETRANSMISSION_TAG
func (h *sentPacketHistory) UpdatePacketNumberMapping(mapping packet_setting.PacketNumberMapping) {

	for i, p := range h.packets {
		if p == nil {
			continue
		}
		if p.PacketNumber == protocol.PacketNumber(mapping.OriginalPacketNumber) {

			index_for_insertion := 0
			for j, p := range h.packets {
				if p == nil {
					continue
				}
				if p.PacketNumber > protocol.PacketNumber(mapping.NewPacketNumber) {
					index_for_insertion = j
					break
				}
			}

			history_without := append(h.packets[:i], h.packets[i+1:]...)
			p.PacketNumber = protocol.PacketNumber(mapping.NewPacketNumber)
			if p.PacketNumber > h.highestPacketNumber {
				h.highestPacketNumber = p.PacketNumber
			}
			p.SendTime = time.Now() // time.Unix(0, 1<<63-1) // TODO: remove
			h.packets = append(history_without[:index_for_insertion], append([]*packet{p}, history_without[index_for_insertion:]...)...)
			h.translation_map[protocol.PacketNumber(mapping.NewPacketNumber)] = protocol.PacketNumber(mapping.OriginalPacketNumber)
			return
		}
	}
}

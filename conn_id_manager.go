package quic

import (
	"fmt"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/qerr"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/utils"
	list "github.com/danielpfeifer02/quic-go-prio-packs/internal/utils/linkedlist"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/wire"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

type newConnID struct {
	SequenceNumber      uint64
	ConnectionID        protocol.ConnectionID
	StatelessResetToken protocol.StatelessResetToken
}

type connIDManager struct {
	queue list.List[newConnID]

	handshakeComplete         bool
	activeSequenceNumber      uint64
	highestRetired            uint64
	activeConnectionID        protocol.ConnectionID
	activeStatelessResetToken *protocol.StatelessResetToken

	// We change the connection ID after sending on average
	// protocol.PacketsPerConnectionID packets. The actual value is randomized
	// hide the packet loss rate from on-path observers.
	rand                   utils.Rand
	packetsSinceLastChange uint32
	packetsPerConnectionID uint32

	addStatelessResetToken    func(protocol.StatelessResetToken)
	removeStatelessResetToken func(protocol.StatelessResetToken)
	queueControlFrame         func(wire.Frame)
}

func newConnIDManager(
	initialDestConnID protocol.ConnectionID,
	addStatelessResetToken func(protocol.StatelessResetToken),
	removeStatelessResetToken func(protocol.StatelessResetToken),
	queueControlFrame func(wire.Frame),
) *connIDManager {
	return &connIDManager{
		activeConnectionID:        initialDestConnID,
		addStatelessResetToken:    addStatelessResetToken,
		removeStatelessResetToken: removeStatelessResetToken,
		queueControlFrame:         queueControlFrame,
	}
}

func (h *connIDManager) AddFromPreferredAddress(connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	return h.addConnectionID(1, connID, resetToken)
}

func (h *connIDManager) Add(f *wire.NewConnectionIDFrame) error {
	if err := h.add(f); err != nil {
		return err
	}
	if h.queue.Len() >= protocol.MaxActiveConnectionIDs {
		return &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}
	}
	return nil
}

func (h *connIDManager) add(f *wire.NewConnectionIDFrame) error {
	// If the NEW_CONNECTION_ID frame is reordered, such that its sequence number is smaller than the currently active
	// connection ID or if it was already retired, send the RETIRE_CONNECTION_ID frame immediately.
	if f.SequenceNumber < h.activeSequenceNumber || f.SequenceNumber < h.highestRetired {
		h.queueControlFrame(&wire.RetireConnectionIDFrame{
			SequenceNumber: f.SequenceNumber,
		})
		return nil
	}

	// Retire elements in the queue.
	// Doesn't retire the active connection ID.
	if f.RetirePriorTo > h.highestRetired {
		var next *list.Element[newConnID]
		for el := h.queue.Front(); el != nil; el = next {
			if el.Value.SequenceNumber >= f.RetirePriorTo {
				break
			}
			next = el.Next()
			h.queueControlFrame(&wire.RetireConnectionIDFrame{
				SequenceNumber: el.Value.SequenceNumber,
			})
			h.queue.Remove(el)
		}
		h.highestRetired = f.RetirePriorTo
	}

	if f.SequenceNumber == h.activeSequenceNumber {
		return nil
	}

	if err := h.addConnectionID(f.SequenceNumber, f.ConnectionID, f.StatelessResetToken); err != nil {
		return err
	}

	// Retire the active connection ID, if necessary.
	if h.activeSequenceNumber < f.RetirePriorTo {
		// The queue is guaranteed to have at least one element at this point.
		h.updateConnectionID()
	}
	return nil
}

func (h *connIDManager) addConnectionID(seq uint64, connID protocol.ConnectionID, resetToken protocol.StatelessResetToken) error {
	// insert a new element at the end
	if h.queue.Len() == 0 || h.queue.Back().Value.SequenceNumber < seq {
		h.queue.PushBack(newConnID{
			SequenceNumber:      seq,
			ConnectionID:        connID,
			StatelessResetToken: resetToken,
		})
		return nil
	}
	// insert a new element somewhere in the middle
	for el := h.queue.Front(); el != nil; el = el.Next() {
		if el.Value.SequenceNumber == seq {
			if el.Value.ConnectionID != connID {
				return fmt.Errorf("received conflicting connection IDs for sequence number %d", seq)
			}
			if el.Value.StatelessResetToken != resetToken {
				return fmt.Errorf("received conflicting stateless reset tokens for sequence number %d", seq)
			}
			break
		}
		if el.Value.SequenceNumber > seq {
			h.queue.InsertBefore(newConnID{
				SequenceNumber:      seq,
				ConnectionID:        connID,
				StatelessResetToken: resetToken,
			}, el)
			break
		}
	}
	return nil
}

func (h *connIDManager) updateConnectionID() {
	h.queueControlFrame(&wire.RetireConnectionIDFrame{
		SequenceNumber: h.activeSequenceNumber,
	})
	h.highestRetired = max(h.highestRetired, h.activeSequenceNumber)
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}

	qf := h.queue.Front()
	// //fmt.Printf("Removing conn ID with prio %d\n", qf.Value.ConnectionID.Bytes()[0])
	front := h.queue.Remove(qf)
	h.activeSequenceNumber = front.SequenceNumber
	h.activeConnectionID = front.ConnectionID
	h.activeStatelessResetToken = &front.StatelessResetToken
	h.packetsSinceLastChange = 0
	h.packetsPerConnectionID = protocol.PacketsPerConnectionID/2 + uint32(h.rand.Int31n(protocol.PacketsPerConnectionID))
	h.addStatelessResetToken(*h.activeStatelessResetToken)
}

func (h *connIDManager) Close() {
	if h.activeStatelessResetToken != nil {
		h.removeStatelessResetToken(*h.activeStatelessResetToken)
	}
}

// is called when the server performs a Retry
// and when the server changes the connection ID in the first Initial sent
func (h *connIDManager) ChangeInitialConnID(newConnID protocol.ConnectionID) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeConnectionID = newConnID
}

// is called when the server provides a stateless reset token in the transport parameters
func (h *connIDManager) SetStatelessResetToken(token protocol.StatelessResetToken) {
	if h.activeSequenceNumber != 0 {
		panic("expected first connection ID to have sequence number 0")
	}
	h.activeStatelessResetToken = &token
	h.addStatelessResetToken(token)
}

func (h *connIDManager) SentPacket() {
	h.packetsSinceLastChange++
}

func (h *connIDManager) shouldUpdateConnID() bool {
	if !h.handshakeComplete {
		return false
	}
	// initiate the first change as early as possible (after handshake completion)
	if h.queue.Len() > 0 && h.activeSequenceNumber == 0 {
		return true
	}
	// For later changes, only change if
	// 1. The queue of connection IDs is filled more than 50%.
	// 2. We sent at least PacketsPerConnectionID packets
	// 3. The current connection ID is not the only one with the priority of the current connection ID
	currentPriority := Priority(h.activeConnectionID.Bytes()[0])
	onlyIDOfPriority := true
	for el := h.queue.Front(); el != nil; el = el.Next() {
		if el.Value.ConnectionID.Bytes()[0] == byte(currentPriority) {
			onlyIDOfPriority = false
			break
		}
	}
	// //fmt.Printf("Trying to remove priority %d, onlyIDOfPriority: %t\n", currentPriority, onlyIDOfPriority)
	return 2*h.queue.Len() >= protocol.MaxActiveConnectionIDs &&
		h.packetsSinceLastChange >= h.packetsPerConnectionID &&
		!onlyIDOfPriority
}

// PRIO_PACKS_TAG
// To keep old functionality:
// prio == priority_setting.NoPriority means user does not care about priority
// prio == priority_setting.LowPriority means user wants to switch to low priority connection ID
// prio == priority_setting.HighPriority means user wants to switch to high priority connection ID
func (h *connIDManager) Get(prio Priority) protocol.ConnectionID {
	if h.shouldUpdateConnID() {
		h.updateConnectionID()
	}
	// TODO: can this also be done before checking "shouldUpdateConnID"?
	// (regarding edge case in the beginning with id == 0)
	if prio != priority_setting.NoPriority {
		h.SwitchToPriorityID(prio)
	}
	return h.activeConnectionID
}

func (h *connIDManager) SetHandshakeComplete() {
	h.handshakeComplete = true
}

// PRIO_PACKS_TAG
func (h *connIDManager) SwitchToPriorityID(prio Priority) {
	currentConnId := h.activeConnectionID
	if currentConnId.Bytes()[0] == byte(prio) || h.queue.Len() == 0 {
		return
	}

	for i := 0; i < h.queue.Len(); i++ {
		// save the current state
		oldConnID := currentConnId
		oldSeq := h.activeSequenceNumber
		oldResetToken := *h.activeStatelessResetToken

		// get the next potential state
		potential := h.queue.Front().Value
		h.queue.Remove(h.queue.Front())

		h.queue.PushBack(newConnID{
			SequenceNumber:      oldSeq,
			ConnectionID:        oldConnID,
			StatelessResetToken: oldResetToken,
		})

		// if the priority matches, switch to that state
		// otherwise push current one back again and try the next one
		if potential.ConnectionID.Bytes()[0] == byte(prio) {
			h.activeConnectionID = potential.ConnectionID
			h.activeSequenceNumber = potential.SequenceNumber
			h.activeStatelessResetToken = &potential.StatelessResetToken
			h.packetsSinceLastChange = 0
			return
		}
	}
}

package quic

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"

	crypto_settings "golang.org/x/crypto"
	"golang.org/x/exp/rand"

	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/ackhandler"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/handshake"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/qerr"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/wire"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

var errNothingToPack = errors.New("nothing to pack")

type packer interface {
	PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error)
	PackAckOnlyPacket(maxPacketSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)
	AppendPacket(buf *packetBuffer, maxPacketSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, error)
	MaybePackProbePacket(protocol.EncryptionLevel, protocol.ByteCount, protocol.Version) (*coalescedPacket, error)
	PackConnectionClose(*qerr.TransportError, protocol.ByteCount, protocol.Version) (*coalescedPacket, error)
	PackApplicationClose(*qerr.ApplicationError, protocol.ByteCount, protocol.Version) (*coalescedPacket, error)
	PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, v protocol.Version) (shortHeaderPacket, *packetBuffer, error)

	SetToken([]byte)
}

type sealer interface {
	handshake.LongHeaderSealer
}

type payload struct {
	streamFrames []ackhandler.StreamFrame
	frames       []ackhandler.Frame
	ack          *wire.AckFrame
	length       protocol.ByteCount

	// DATAGRAM_PRIO_TAG
	priority priority_setting.Priority
}

type longHeaderPacket struct {
	header       *wire.ExtendedHeader
	ack          *wire.AckFrame
	frames       []ackhandler.Frame
	streamFrames []ackhandler.StreamFrame // only used for 0-RTT packets

	length protocol.ByteCount
}

type shortHeaderPacket struct {
	PacketNumber         protocol.PacketNumber
	Frames               []ackhandler.Frame
	StreamFrames         []ackhandler.StreamFrame
	Ack                  *wire.AckFrame
	Length               protocol.ByteCount
	IsPathMTUProbePacket bool

	// used for logging
	DestConnID      protocol.ConnectionID
	PacketNumberLen protocol.PacketNumberLen
	KeyPhase        protocol.KeyPhaseBit
}

func (p *shortHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.Frames) }

type coalescedPacket struct {
	buffer         *packetBuffer
	longHdrPackets []*longHeaderPacket
	shortHdrPacket *shortHeaderPacket
}

// IsOnlyShortHeaderPacket says if this packet only contains a short header packet (and no long header packets).
func (p *coalescedPacket) IsOnlyShortHeaderPacket() bool {
	return len(p.longHdrPackets) == 0 && p.shortHdrPacket != nil
}

func (p *longHeaderPacket) EncryptionLevel() protocol.EncryptionLevel {
	//nolint:exhaustive // Will never be called for Retry packets (and they don't have encrypted data).
	switch p.header.Type {
	case protocol.PacketTypeInitial:
		return protocol.EncryptionInitial
	case protocol.PacketTypeHandshake:
		return protocol.EncryptionHandshake
	case protocol.PacketType0RTT:
		return protocol.Encryption0RTT
	default:
		panic("can't determine encryption level")
	}
}

func (p *longHeaderPacket) IsAckEliciting() bool { return ackhandler.HasAckElicitingFrames(p.frames) }

type packetNumberManager interface {
	PeekPacketNumber(protocol.EncryptionLevel) (protocol.PacketNumber, protocol.PacketNumberLen)
	PopPacketNumber(protocol.EncryptionLevel) protocol.PacketNumber
}

type sealingManager interface {
	GetInitialSealer() (handshake.LongHeaderSealer, error)
	GetHandshakeSealer() (handshake.LongHeaderSealer, error)
	Get0RTTSealer() (handshake.LongHeaderSealer, error)
	Get1RTTSealer() (handshake.ShortHeaderSealer, error)
}

type frameSource interface {
	HasData() bool
	AppendStreamFrames([]ackhandler.StreamFrame, protocol.ByteCount, protocol.Version) ([]ackhandler.StreamFrame, protocol.ByteCount)
	AppendControlFrames([]ackhandler.Frame, protocol.ByteCount, protocol.Version) ([]ackhandler.Frame, protocol.ByteCount)
}

type ackFrameSource interface {
	GetAckFrame(encLevel protocol.EncryptionLevel, onlyIfQueued bool) *wire.AckFrame
}

type packetPacker struct {
	// PRIO_PACKS_TAG
	connection Connection
	srcConnID  protocol.ConnectionID
	// PRIO_PACKS_TAG
	getDestConnID func(Priority) protocol.ConnectionID

	perspective protocol.Perspective
	cryptoSetup sealingManager

	initialStream   cryptoStream
	handshakeStream cryptoStream

	token []byte

	pnManager           packetNumberManager
	framer              frameSource
	acks                ackFrameSource
	datagramQueue       *datagramQueue
	retransmissionQueue *retransmissionQueue
	rand                rand.Rand

	numNonAckElicitingAcks int
}

var _ packer = &packetPacker{}

func newPacketPacker(
	associatedConnection Connection,
	srcConnID protocol.ConnectionID,
	// PRIO_PACKS_TAG
	getDestConnID func(Priority) protocol.ConnectionID,
	initialStream, handshakeStream cryptoStream,
	packetNumberManager packetNumberManager,
	retransmissionQueue *retransmissionQueue,
	cryptoSetup sealingManager,
	framer frameSource,
	acks ackFrameSource,
	datagramQueue *datagramQueue,
	perspective protocol.Perspective,
) *packetPacker {
	var b [8]byte
	_, _ = crand.Read(b[:])

	return &packetPacker{
		// PRIO_PACKS_TAG
		connection:          associatedConnection,
		cryptoSetup:         cryptoSetup,
		getDestConnID:       getDestConnID,
		srcConnID:           srcConnID,
		initialStream:       initialStream,
		handshakeStream:     handshakeStream,
		retransmissionQueue: retransmissionQueue,
		datagramQueue:       datagramQueue,
		perspective:         perspective,
		framer:              framer,
		acks:                acks,
		rand:                *rand.New(rand.NewSource(binary.BigEndian.Uint64(b[:]))),
		pnManager:           packetNumberManager,
	}
}

// PackConnectionClose packs a packet that closes the connection with a transport error.
func (p *packetPacker) PackConnectionClose(e *qerr.TransportError, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	// TODO: verify that Unlock() is called AFTER p.packConnectionClose(...) is called
	defer p.connection.Unlock()

	var reason string
	// don't send details of crypto errors
	if !e.ErrorCode.IsCryptoError() {
		reason = e.ErrorMessage
	}
	return p.packConnectionClose(false, uint64(e.ErrorCode), e.FrameType, reason, maxPacketSize, v)
}

// PackApplicationClose packs a packet that closes the connection with an application error.
func (p *packetPacker) PackApplicationClose(e *qerr.ApplicationError, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	// TODO: verify that Unlock() is called AFTER p.packConnectionClose(...) is called
	defer p.connection.Unlock()

	return p.packConnectionClose(true, uint64(e.ErrorCode), 0, e.ErrorMessage, maxPacketSize, v)
}

func (p *packetPacker) packConnectionClose(
	isApplicationError bool,
	errorCode uint64,
	frameType uint64,
	reason string,
	maxPacketSize protocol.ByteCount,
	v protocol.Version,
) (*coalescedPacket, error) {
	var sealers [4]sealer
	var hdrs [3]*wire.ExtendedHeader
	var payloads [4]payload
	var size protocol.ByteCount
	var connID protocol.ConnectionID
	var oneRTTPacketNumber protocol.PacketNumber
	var oneRTTPacketNumberLen protocol.PacketNumberLen
	var keyPhase protocol.KeyPhaseBit // only set for 1-RTT
	var numLongHdrPackets uint8
	encLevels := [4]protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption0RTT, protocol.Encryption1RTT}
	for i, encLevel := range encLevels {
		if p.perspective == protocol.PerspectiveServer && encLevel == protocol.Encryption0RTT {
			continue
		}
		ccf := &wire.ConnectionCloseFrame{
			IsApplicationError: isApplicationError,
			ErrorCode:          errorCode,
			FrameType:          frameType,
			ReasonPhrase:       reason,
		}

		// don't send application errors in Initial or Handshake packets
		if isApplicationError && (encLevel == protocol.EncryptionInitial || encLevel == protocol.EncryptionHandshake) {
			ccf.IsApplicationError = false
			ccf.ErrorCode = uint64(qerr.ApplicationErrorErrorCode)
			ccf.ReasonPhrase = ""
		}
		pl := payload{
			frames: []ackhandler.Frame{{Frame: ccf}},
			length: ccf.Length(v),

			// PRIO_PACKS_TAG
			priority: priority_setting.PrioConnectionClosePacket,
		}

		var sealer sealer
		var err error
		switch encLevel {
		case protocol.EncryptionInitial:
			sealer, err = p.cryptoSetup.GetInitialSealer()
		case protocol.EncryptionHandshake:
			sealer, err = p.cryptoSetup.GetHandshakeSealer()
		case protocol.Encryption0RTT:
			sealer, err = p.cryptoSetup.Get0RTTSealer()
		case protocol.Encryption1RTT:
			var s handshake.ShortHeaderSealer
			s, err = p.cryptoSetup.Get1RTTSealer()
			if err == nil {
				keyPhase = s.KeyPhase()
			}
			sealer = s
		}
		if err == handshake.ErrKeysNotYetAvailable || err == handshake.ErrKeysDropped {
			continue
		}
		if err != nil {
			return nil, err
		}
		sealers[i] = sealer
		var hdr *wire.ExtendedHeader
		if encLevel == protocol.Encryption1RTT {
			// PRIO_PACKS_TAG
			// TODOME: necessary to adapt that to stream? connection close
			// should probably always be sent with high prio connection id
			connID = p.getDestConnID(pl.priority)
			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			size += p.shortHeaderPacketLength(connID, oneRTTPacketNumberLen, pl)
		} else {
			hdr = p.getLongHeader(encLevel, v)
			hdrs[i] = hdr
			size += p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
			numLongHdrPackets++
		}
		payloads[i] = pl
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, numLongHdrPackets),
	}
	for i, encLevel := range encLevels {
		if sealers[i] == nil {
			continue
		}
		var paddingLen protocol.ByteCount
		if encLevel == protocol.EncryptionInitial {
			paddingLen = p.initialPaddingLen(payloads[i].frames, size, maxPacketSize)
		}
		if encLevel == protocol.Encryption1RTT {
			shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, keyPhase, payloads[i], paddingLen, maxPacketSize, sealers[i], false, v)
			if err != nil {
				return nil, err
			}
			packet.shortHdrPacket = &shp
		} else {
			longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdrs[i], payloads[i], paddingLen, encLevel, sealers[i], v)
			if err != nil {
				return nil, err
			}
			packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
		}
	}
	return packet, nil
}

// longHeaderPacketLength calculates the length of a serialized long header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) longHeaderPacketLength(hdr *wire.ExtendedHeader, pl payload, v protocol.Version) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(hdr.PacketNumberLen)
	if pl.length < 4-pnLen {
		paddingLen = 4 - pnLen - pl.length
	}
	return hdr.GetLength(v) + pl.length + paddingLen
}

// shortHeaderPacketLength calculates the length of a serialized short header packet.
// It takes into account that packets that have a tiny payload need to be padded,
// such that len(payload) + packet number len >= 4 + AEAD overhead
func (p *packetPacker) shortHeaderPacketLength(connID protocol.ConnectionID, pnLen protocol.PacketNumberLen, pl payload) protocol.ByteCount {
	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
	}
	return wire.ShortHeaderLen(connID, pnLen) + pl.length + paddingLen
}

// size is the expected size of the packet, if no padding was applied.
func (p *packetPacker) initialPaddingLen(frames []ackhandler.Frame, currentSize, maxPacketSize protocol.ByteCount) protocol.ByteCount {
	// For the server, only ack-eliciting Initial packets need to be padded.
	if p.perspective == protocol.PerspectiveServer && !ackhandler.HasAckElicitingFrames(frames) {
		return 0
	}
	if currentSize >= maxPacketSize {
		return 0
	}
	return maxPacketSize - currentSize
}

// PackCoalescedPacket packs a new packet.
// It packs an Initial / Handshake if there is data to send in these packet number spaces.
// It should only be called before the handshake is confirmed.
func (p *packetPacker) PackCoalescedPacket(onlyAck bool, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	defer p.connection.Unlock()

	var (
		initialHdr, handshakeHdr, zeroRTTHdr                            *wire.ExtendedHeader
		initialPayload, handshakePayload, zeroRTTPayload, oneRTTPayload payload
		oneRTTPacketNumber                                              protocol.PacketNumber
		oneRTTPacketNumberLen                                           protocol.PacketNumberLen
	)
	// Try packing an Initial packet.
	initialSealer, err := p.cryptoSetup.GetInitialSealer()
	if err != nil && err != handshake.ErrKeysDropped {
		return nil, err
	}
	var size protocol.ByteCount
	if initialSealer != nil {
		initialHdr, initialPayload = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(initialSealer.Overhead()), protocol.EncryptionInitial, onlyAck, true, v)
		if initialPayload.length > 0 {
			size += p.longHeaderPacketLength(initialHdr, initialPayload, v) + protocol.ByteCount(initialSealer.Overhead())
		}
	}

	// Add a Handshake packet.
	var handshakeSealer sealer
	if (onlyAck && size == 0) || (!onlyAck && size < maxPacketSize-protocol.MinCoalescedPacketSize) {
		var err error
		handshakeSealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if handshakeSealer != nil {
			handshakeHdr, handshakePayload = p.maybeGetCryptoPacket(maxPacketSize-size-protocol.ByteCount(handshakeSealer.Overhead()), protocol.EncryptionHandshake, onlyAck, size == 0, v)
			if handshakePayload.length > 0 {
				s := p.longHeaderPacketLength(handshakeHdr, handshakePayload, v) + protocol.ByteCount(handshakeSealer.Overhead())
				size += s
			}
		}
	}

	// Add a 0-RTT / 1-RTT packet.
	var zeroRTTSealer sealer
	var oneRTTSealer handshake.ShortHeaderSealer
	var connID protocol.ConnectionID
	var kp protocol.KeyPhaseBit
	if (onlyAck && size == 0) || (!onlyAck && size < maxPacketSize-protocol.MinCoalescedPacketSize) {
		var err error
		oneRTTSealer, err = p.cryptoSetup.Get1RTTSealer()
		if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
			return nil, err
		}
		if err == nil { // 1-RTT
			kp = oneRTTSealer.KeyPhase()

			// PRIO_PACKS_TAG
			connIDDummy, err := protocol.GenerateConnectionID(int(protocol.PriorityConnIDLen))
			if err != nil {
				panic("error generating dummy connection id")
			}

			oneRTTPacketNumber, oneRTTPacketNumberLen = p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
			hdrLen := wire.ShortHeaderLen(connIDDummy, oneRTTPacketNumberLen)
			oneRTTPayload = p.maybeGetShortHeaderPacket(oneRTTSealer, hdrLen, maxPacketSize-size, onlyAck, size == 0, v)
			if oneRTTPayload.length > 0 {
				size += p.shortHeaderPacketLength(connIDDummy, oneRTTPacketNumberLen, oneRTTPayload) + protocol.ByteCount(oneRTTSealer.Overhead())
			}

			// PRIO_PACKS_TAG
			// now we can go through all streamFrames, check the stream ids and look
			// up their priority
			prio := priority_setting.NoPriority
			for i := range oneRTTPayload.streamFrames {
				f := &oneRTTPayload.streamFrames[i]
				sid := f.Frame.StreamID
				prio_tmp := p.GetPriority(sid)
				prio = max(prio, prio_tmp)
			}

			// DATAGRAM_PRIO_TAG
			// TODOME: use only the payload priority sufficient?
			prio = max(prio, oneRTTPayload.priority)
			connID = p.getDestConnID(prio)

			// BPF_MAP_TAG
			if packet_setting.ConnectionUpdateBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
				packet_setting.ConnectionUpdateBPFHandler(connID.Bytes(), uint8(connID.Len()), p.connection)
			}

		} else if p.perspective == protocol.PerspectiveClient && !onlyAck { // 0-RTT packets can't contain ACK frames
			var err error
			zeroRTTSealer, err = p.cryptoSetup.Get0RTTSealer()
			if err != nil && err != handshake.ErrKeysDropped && err != handshake.ErrKeysNotYetAvailable {
				return nil, err
			}
			if zeroRTTSealer != nil {
				zeroRTTHdr, zeroRTTPayload = p.maybeGetAppDataPacketFor0RTT(zeroRTTSealer, maxPacketSize-size, v)
				if zeroRTTPayload.length > 0 {
					size += p.longHeaderPacketLength(zeroRTTHdr, zeroRTTPayload, v) + protocol.ByteCount(zeroRTTSealer.Overhead())
				}
			}
		}
	}

	if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 && oneRTTPayload.length == 0 {
		return nil, nil
	}

	buffer := getPacketBuffer()
	packet := &coalescedPacket{
		buffer:         buffer,
		longHdrPackets: make([]*longHeaderPacket, 0, 3),
	}
	if initialPayload.length > 0 {
		padding := p.initialPaddingLen(initialPayload.frames, size, maxPacketSize)
		cont, err := p.appendLongHeaderPacket(buffer, initialHdr, initialPayload, padding, protocol.EncryptionInitial, initialSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if handshakePayload.length > 0 {
		cont, err := p.appendLongHeaderPacket(buffer, handshakeHdr, handshakePayload, 0, protocol.EncryptionHandshake, handshakeSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, cont)
	}
	if zeroRTTPayload.length > 0 {
		longHdrPacket, err := p.appendLongHeaderPacket(buffer, zeroRTTHdr, zeroRTTPayload, 0, protocol.Encryption0RTT, zeroRTTSealer, v)
		if err != nil {
			return nil, err
		}
		packet.longHdrPackets = append(packet.longHdrPackets, longHdrPacket)
	} else if oneRTTPayload.length > 0 {
		// SINGLE_STREAM_PACKET_TAG
		if initialPayload.length == 0 && handshakePayload.length == 0 && zeroRTTPayload.length == 0 { // TODO: remove. This is just to avoid mixing long and short header packets in the same coalesced packet.
			shp, err := p.appendShortHeaderPacket(buffer, connID, oneRTTPacketNumber, oneRTTPacketNumberLen, kp, oneRTTPayload, 0, maxPacketSize, oneRTTSealer, false, v)
			if err != nil {
				return nil, err
			}
			packet.shortHdrPacket = &shp
		}
	}
	return packet, nil
}

// PackAckOnlyPacket packs a packet containing only an ACK in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) PackAckOnlyPacket(maxPacketSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	defer p.connection.Unlock()

	buf := getPacketBuffer()
	packet, err := p.appendPacket(buf, true, maxPacketSize, v)
	return packet, buf, err
}

// AppendPacket packs a packet in the application data packet number space.
// It should be called after the handshake is confirmed.
func (p *packetPacker) AppendPacket(buf *packetBuffer, maxPacketSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	defer p.connection.Unlock()

	return p.appendPacket(buf, false, maxPacketSize, v)
}

func (p *packetPacker) appendPacket(buf *packetBuffer, onlyAck bool, maxPacketSize protocol.ByteCount, v protocol.Version) (shortHeaderPacket, error) {
	sealer, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, err
	}
	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)

	// PRIO_PACKS_TAG
	connIDDummy, err := protocol.GenerateConnectionID(int(protocol.PriorityConnIDLen))
	if err != nil {
		panic("error generating dummy connection id")
	}

	hdrLen := wire.ShortHeaderLen(connIDDummy, pnLen)
	pl := p.maybeGetShortHeaderPacket(sealer, hdrLen, maxPacketSize, onlyAck, true, v)
	if pl.length == 0 {
		return shortHeaderPacket{}, errNothingToPack
	}
	kp := sealer.KeyPhase()

	// PRIO_PACKS_TAG
	// now we can go through all streamFrames, check the stream ids and look
	// up thei priority
	prio := priority_setting.NoPriority
	for i := range pl.streamFrames {
		f := &pl.streamFrames[i]
		sid := f.Frame.StreamID
		prio_tmp := p.GetPriority(sid)
		prio = max(prio, prio_tmp)
	}

	// DATAGRAM_PRIO_TAG
	// TODOME: use only the payload priority sufficient?
	prio = max(prio, pl.priority)
	connID := p.getDestConnID(prio)

	// BPF_MAP_TAG
	if packet_setting.ConnectionUpdateBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
		packet_setting.ConnectionUpdateBPFHandler(connID.Bytes(), uint8(connID.Len()), p.connection)
	}

	return p.appendShortHeaderPacket(buf, connID, pn, pnLen, kp, pl, 0, maxPacketSize, sealer, false, v)
}

func (p *packetPacker) maybeGetCryptoPacket(maxPacketSize protocol.ByteCount, encLevel protocol.EncryptionLevel, onlyAck, ackAllowed bool, v protocol.Version) (*wire.ExtendedHeader, payload) {
	if onlyAck {
		if ack := p.acks.GetAckFrame(encLevel, true); ack != nil {
			return p.getLongHeader(encLevel, v), payload{
				ack:    ack,
				length: ack.Length(v),
			}
		}
		return nil, payload{}
	}

	var s cryptoStream
	var handler ackhandler.FrameHandler
	var hasRetransmission bool
	//nolint:exhaustive // Initial and Handshake are the only two encryption levels here.
	switch encLevel {
	case protocol.EncryptionInitial:
		s = p.initialStream
		handler = p.retransmissionQueue.InitialAckHandler()
		hasRetransmission = p.retransmissionQueue.HasInitialData()
	case protocol.EncryptionHandshake:
		s = p.handshakeStream
		handler = p.retransmissionQueue.HandshakeAckHandler()
		hasRetransmission = p.retransmissionQueue.HasHandshakeData()
	}

	hasData := s.HasData()
	var ack *wire.AckFrame
	if ackAllowed {
		ack = p.acks.GetAckFrame(encLevel, !hasRetransmission && !hasData)
	}
	if !hasData && !hasRetransmission && ack == nil {
		// nothing to send
		return nil, payload{}
	}

	var pl payload
	// DATAGRAM_PRIO_TAG
	pl.priority = priority_setting.NoPriority

	if ack != nil {
		pl.ack = ack
		pl.length = ack.Length(v)
		maxPacketSize -= pl.length
	}
	hdr := p.getLongHeader(encLevel, v)
	maxPacketSize -= hdr.GetLength(v)
	if hasRetransmission {
		for {
			var f ackhandler.Frame
			//nolint:exhaustive // 0-RTT packets can't contain any retransmission.s
			switch encLevel {
			case protocol.EncryptionInitial:
				f.Frame = p.retransmissionQueue.GetInitialFrame(maxPacketSize, v)
				f.Handler = p.retransmissionQueue.InitialAckHandler()
			case protocol.EncryptionHandshake:
				f.Frame = p.retransmissionQueue.GetHandshakeFrame(maxPacketSize, v)
				f.Handler = p.retransmissionQueue.HandshakeAckHandler()
			}
			if f.Frame == nil {
				break
			}
			pl.frames = append(pl.frames, f)
			frameLen := f.Frame.Length(v)
			pl.length += frameLen
			maxPacketSize -= frameLen
		}
	} else if s.HasData() {
		cf := s.PopCryptoFrame(maxPacketSize)
		pl.frames = []ackhandler.Frame{{Frame: cf, Handler: handler}}
		pl.length += cf.Length(v)
	}
	return hdr, pl
}

func (p *packetPacker) maybeGetAppDataPacketFor0RTT(sealer sealer, maxPacketSize protocol.ByteCount, v protocol.Version) (*wire.ExtendedHeader, payload) {
	if p.perspective != protocol.PerspectiveClient {
		return nil, payload{}
	}

	hdr := p.getLongHeader(protocol.Encryption0RTT, v)
	maxPayloadSize := maxPacketSize - hdr.GetLength(v) - protocol.ByteCount(sealer.Overhead())
	return hdr, p.maybeGetAppDataPacket(maxPayloadSize, false, false, v)
}

func (p *packetPacker) maybeGetShortHeaderPacket(sealer handshake.ShortHeaderSealer, hdrLen protocol.ByteCount, maxPacketSize protocol.ByteCount, onlyAck, ackAllowed bool, v protocol.Version) payload {
	maxPayloadSize := maxPacketSize - hdrLen - protocol.ByteCount(sealer.Overhead())
	if p.connection.RemoteAddr().String() != packet_setting.SERVER_ADDR && p.framer.HasData() {
		packet_setting.DebugPrintln("BBBB shpacket")
	}
	return p.maybeGetAppDataPacket(maxPayloadSize, onlyAck, ackAllowed, v)
}

func (p *packetPacker) maybeGetAppDataPacket(maxPayloadSize protocol.ByteCount, onlyAck, ackAllowed bool, v protocol.Version) payload {
	pl := p.composeNextPacket(maxPayloadSize, onlyAck, ackAllowed, v)

	// check if we have anything to send
	if len(pl.frames) == 0 && len(pl.streamFrames) == 0 {
		if pl.ack == nil {
			return payload{}
		}
		// the packet only contains an ACK
		if p.numNonAckElicitingAcks >= protocol.MaxNonAckElicitingAcks {
			ping := &wire.PingFrame{} // TODONOW: pings correctly handled?
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: ping})
			pl.length += ping.Length(v)
			p.numNonAckElicitingAcks = 0
		} else {
			p.numNonAckElicitingAcks++
		}
	} else {
		p.numNonAckElicitingAcks = 0
	}
	return pl
}

func (p *packetPacker) composeNextPacket(maxFrameSize protocol.ByteCount, onlyAck, ackAllowed bool, v protocol.Version) payload {

	if onlyAck {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, true); ack != nil {
			return payload{ack: ack, length: ack.Length(v)}
		}
		return payload{}
	}

	hasData := p.framer.HasData()
	hasRetransmission := p.retransmissionQueue.HasAppData()

	var hasAck bool
	var pl payload
	// DATAGRAM_PRIO_TAG
	pl.priority = priority_setting.NoPriority

	if ackAllowed {
		if ack := p.acks.GetAckFrame(protocol.Encryption1RTT, !hasRetransmission && !hasData); ack != nil {
			pl.ack = ack
			pl.length += ack.Length(v)
			hasAck = true

			// STREAM_ONLY_TAG
			return pl
		}
	}

	if p.datagramQueue != nil {
		if f := p.datagramQueue.Peek(); f != nil {
			size := f.Length(v)
			if size <= maxFrameSize-pl.length { // DATAGRAM frame fits
				pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
				pl.length += size

				// DATAGRAM_PRIO_TAG
				pl.priority = max(pl.priority, f.Priority)

				p.datagramQueue.Pop()

				// STREAM_ONLY_TAG
				// directly return so that the datagram is sent in a separate packet
				// (also only one datagram will be sent per packet)
				return pl

			} else if !hasAck {
				// The DATAGRAM frame doesn't fit, and the packet doesn't contain an ACK.
				// Discard this frame. There's no point in retrying this in the next packet,
				// as it's unlikely that the available packet size will increase.
				p.datagramQueue.Pop()
			}
			// If the DATAGRAM frame was too large and the packet contained an ACK, we'll try to send it out later.
		}
	}

	if hasAck && !hasData && !hasRetransmission {
		return pl
	}

	if hasRetransmission {
		for {
			remainingLen := maxFrameSize - pl.length
			if remainingLen < protocol.MinStreamFrameSize {
				break
			}
			f := p.retransmissionQueue.GetAppDataFrame(remainingLen, v)
			if f == nil {
				break
			}
			pl.frames = append(pl.frames, ackhandler.Frame{Frame: f, Handler: p.retransmissionQueue.AppDataAckHandler()})
			pl.length += f.Length(v)

			// STREAM_ONLY_TAG
			// RETRANSMISSION_TAG
			// TODO: what exactly is sent here? Any need to leave this function early to
			// TODO: ensure that streams are always sent in a separate packet?
			// TODO: only leave early if its the right connection and bpf stuff is enabled

			if p.connection.LocalAddr().String() == packet_setting.SERVER_ADDR {
				return pl
			}
		}
	}

	if hasData {
		var lengthAdded protocol.ByteCount
		startLen := len(pl.frames)

		// STREAM_ONLY_TAG
		// TODO: are control frames together with stream frames a problem? probably yes...
		pl.frames, lengthAdded = p.framer.AppendControlFrames(pl.frames, maxFrameSize-pl.length, v)
		crypto_settings.Crypto_debug_println("Number of control frames: ", len(pl.frames)-startLen, "Number of total frames: ", len(pl.frames))
		for frame := range pl.frames {
			crypto_settings.Crypto_debug_println("Frame type: ", reflect.TypeOf(pl.frames[frame].Frame))
		}
		pl.length += lengthAdded
		// add handlers for the control frames that were added
		for i := startLen; i < len(pl.frames); i++ {
			switch pl.frames[i].Frame.(type) {
			case *wire.PathChallengeFrame, *wire.PathResponseFrame:
				// Path probing is currently not supported, therefore we don't need to set the OnAcked callback yet.
				// PATH_CHALLENGE and PATH_RESPONSE are never retransmitted.
			default:
				pl.frames[i].Handler = p.retransmissionQueue.AppDataAckHandler()
			}
		}
		// SINGLE_FRAME_TAG
		// If packet already has one frame -> send it
		// if len(pl.frames) > 0 && p.connection.LocalAddr().String() == packet_setting.SERVER_ADDR {
		// 	return pl
		// }

		// STREAM_ONLY_TAG
		// TODO: can there be more than one stream frame in a packet?
		pl.streamFrames, lengthAdded = p.framer.AppendStreamFrames(pl.streamFrames, maxFrameSize-pl.length, v)
		pl.length += lengthAdded

		// STREAM_PER_PACKET_TAG
		// Making sure it's only one stream frame per packet
		if len(pl.streamFrames) > 1 {
			panic("more than one stream frame in a packet")
		}
	}

	return pl
}

func (p *packetPacker) MaybePackProbePacket(encLevel protocol.EncryptionLevel, maxPacketSize protocol.ByteCount, v protocol.Version) (*coalescedPacket, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	defer p.connection.Unlock()

	if encLevel == protocol.Encryption1RTT {
		s, err := p.cryptoSetup.Get1RTTSealer()
		if err != nil {
			return nil, err
		}
		kp := s.KeyPhase()
		// PRIO_PACKS_TAG
		// TODOME: should probe packets consider the priority?
		// for now we can probably omit them since they are rare
		connID := p.getDestConnID(priority_setting.PrioProbePacket)

		// BPF_MAP_TAG
		if packet_setting.ConnectionUpdateBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
			packet_setting.ConnectionUpdateBPFHandler(connID.Bytes(), uint8(connID.Len()), p.connection)
		}

		pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
		hdrLen := wire.ShortHeaderLen(connID, pnLen)
		pl := p.maybeGetAppDataPacket(maxPacketSize-protocol.ByteCount(s.Overhead())-hdrLen, false, true, v)
		if pl.length == 0 {
			return nil, nil
		}
		buffer := getPacketBuffer()
		packet := &coalescedPacket{buffer: buffer}
		shp, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, 0, maxPacketSize, s, false, v)
		if err != nil {
			return nil, err
		}
		packet.shortHdrPacket = &shp
		return packet, nil
	}

	var hdr *wire.ExtendedHeader
	var pl payload
	// DATAGRAM_PRIO_TAG
	pl.priority = priority_setting.NoPriority

	var sealer handshake.LongHeaderSealer
	//nolint:exhaustive // Probe packets are never sent for 0-RTT.
	switch encLevel {
	case protocol.EncryptionInitial:
		var err error
		sealer, err = p.cryptoSetup.GetInitialSealer()
		if err != nil {
			return nil, err
		}
		hdr, pl = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), protocol.EncryptionInitial, false, true, v)
	case protocol.EncryptionHandshake:
		var err error
		sealer, err = p.cryptoSetup.GetHandshakeSealer()
		if err != nil {
			return nil, err
		}
		hdr, pl = p.maybeGetCryptoPacket(maxPacketSize-protocol.ByteCount(sealer.Overhead()), protocol.EncryptionHandshake, false, true, v)
	default:
		panic("unknown encryption level")
	}

	if pl.length == 0 {
		return nil, nil
	}
	buffer := getPacketBuffer()
	packet := &coalescedPacket{buffer: buffer}
	size := p.longHeaderPacketLength(hdr, pl, v) + protocol.ByteCount(sealer.Overhead())
	var padding protocol.ByteCount
	if encLevel == protocol.EncryptionInitial {
		padding = p.initialPaddingLen(pl.frames, size, maxPacketSize)
	}

	longHdrPacket, err := p.appendLongHeaderPacket(buffer, hdr, pl, padding, encLevel, sealer, v)
	if err != nil {
		return nil, err
	}
	packet.longHdrPackets = []*longHeaderPacket{longHdrPacket}
	return packet, nil
}

func (p *packetPacker) PackMTUProbePacket(ping ackhandler.Frame, size protocol.ByteCount, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {

	// PACKET_NUMBER_TAG
	p.connection.Lock()
	defer p.connection.Unlock()

	pl := payload{
		frames: []ackhandler.Frame{ping},
		length: ping.Frame.Length(v),
	}
	buffer := getPacketBuffer()
	s, err := p.cryptoSetup.Get1RTTSealer()
	if err != nil {
		return shortHeaderPacket{}, nil, err
	}
	// PRIO_PACKS_TAG
	// TODOME: should MTU probe packets consider the priority?
	// i guess MTU probing is rare and likely to be high prio
	connID := p.getDestConnID(priority_setting.PrioMTUProbePacket)

	// BPF_MAP_TAG
	if packet_setting.ConnectionUpdateBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
		packet_setting.ConnectionUpdateBPFHandler(connID.Bytes(), uint8(connID.Len()), p.connection)
	}

	pn, pnLen := p.pnManager.PeekPacketNumber(protocol.Encryption1RTT)
	padding := size - p.shortHeaderPacketLength(connID, pnLen, pl) - protocol.ByteCount(s.Overhead())
	kp := s.KeyPhase()
	packet, err := p.appendShortHeaderPacket(buffer, connID, pn, pnLen, kp, pl, padding, size, s, true, v)
	return packet, buffer, err
}

func (p *packetPacker) getLongHeader(encLevel protocol.EncryptionLevel, v protocol.Version) *wire.ExtendedHeader {
	pn, pnLen := p.pnManager.PeekPacketNumber(encLevel)
	hdr := &wire.ExtendedHeader{
		PacketNumber:    pn,
		PacketNumberLen: pnLen,
	}
	hdr.Version = v
	hdr.SrcConnectionID = p.srcConnID
	// PRIO_PACKS_TAG
	// long header packets are always sent with high prio connection id for now
	// since they are not the norm and only used for stuff like initial handshake
	// or retransmissions
	hdr.DestConnectionID = p.getDestConnID(priority_setting.PrioLongHeaderPacket)

	// BPF_MAP_TAG
	if packet_setting.ConnectionUpdateBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
		packet_setting.ConnectionUpdateBPFHandler(hdr.DestConnectionID.Bytes(), uint8(hdr.DestConnectionID.Len()), p.connection)
	}

	//nolint:exhaustive // 1-RTT packets are not long header packets.
	switch encLevel {
	case protocol.EncryptionInitial:
		hdr.Type = protocol.PacketTypeInitial
		hdr.Token = p.token
	case protocol.EncryptionHandshake:
		hdr.Type = protocol.PacketTypeHandshake
	case protocol.Encryption0RTT:
		hdr.Type = protocol.PacketType0RTT
	}
	return hdr
}

func (p *packetPacker) appendLongHeaderPacket(buffer *packetBuffer, header *wire.ExtendedHeader, pl payload, padding protocol.ByteCount, encLevel protocol.EncryptionLevel, sealer sealer, v protocol.Version) (*longHeaderPacket, error) {
	var paddingLen protocol.ByteCount
	pnLen := protocol.ByteCount(header.PacketNumberLen)
	if pl.length < 4-pnLen {
		paddingLen = 4 - pnLen - pl.length
	}
	paddingLen += padding
	header.Length = pnLen + protocol.ByteCount(sealer.Overhead()) + pl.length + paddingLen

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := header.Append(raw, v)
	if err != nil {
		return nil, err
	}
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return nil, err
	}
	raw = p.encryptPacket(raw, sealer, header.PacketNumber, payloadOffset, pnLen)
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if pn := p.pnManager.PopPacketNumber(encLevel); pn != header.PacketNumber {
		return nil, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, header.PacketNumber)
	}

	// PACKET_NUMBER_TAG
	if packet_setting.PacketNumberIncrementBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
		// Handle the change of packet number by calling the BPF handler function
		// defined by the user who knows about the specific BPF setup
		packet_setting.PacketNumberIncrementBPFHandler(int64(header.PacketNumber), p.connection)
	}

	return &longHeaderPacket{
		header:       header,
		ack:          pl.ack,
		frames:       pl.frames,
		streamFrames: pl.streamFrames,
		length:       protocol.ByteCount(len(raw)),
	}, nil
}

func (p *packetPacker) appendShortHeaderPacket(
	buffer *packetBuffer,
	connID protocol.ConnectionID,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	kp protocol.KeyPhaseBit,
	pl payload,
	padding, maxPacketSize protocol.ByteCount,
	sealer sealer,
	isMTUProbePacket bool,
	v protocol.Version,
) (shortHeaderPacket, error) {

	var paddingLen protocol.ByteCount
	if pl.length < 4-protocol.ByteCount(pnLen) {
		paddingLen = 4 - protocol.ByteCount(pnLen) - pl.length
		if !packet_setting.IS_RELAY && !packet_setting.IS_CLIENT {
			fmt.Println("padding len", paddingLen, "pl.length", pl.length, "pnLen", pnLen)
		}
	}
	paddingLen += padding

	startLen := len(buffer.Data)
	raw := buffer.Data[startLen:]
	raw, err := wire.AppendShortHeader(raw, connID, pn, pnLen, kp)
	if err != nil {
		return shortHeaderPacket{}, err
	}
	payloadOffset := protocol.ByteCount(len(raw))

	raw, err = p.appendPacketPayload(raw, pl, paddingLen, v)
	if err != nil {
		return shortHeaderPacket{}, err
	}

	if !isMTUProbePacket {
		seal_overhead := sealer.Overhead()
		// if crypto_turnoff.CRYPTO_TURNED_OFF { // TODONOW: necessary?
		// 	seal_overhead = 0
		// }
		if size := protocol.ByteCount(len(raw) + seal_overhead); size > maxPacketSize {
			return shortHeaderPacket{}, fmt.Errorf("PacketPacker BUG: packet too large (%d bytes, allowed %d bytes)", size, maxPacketSize)
		}
	}
	raw = p.encryptPacket(raw, sealer, pn, payloadOffset, protocol.ByteCount(pnLen))
	buffer.Data = buffer.Data[:len(buffer.Data)+len(raw)]

	if newPN := p.pnManager.PopPacketNumber(protocol.Encryption1RTT); newPN != pn {
		return shortHeaderPacket{}, fmt.Errorf("packetPacker BUG: Peeked and Popped packet numbers do not match: expected %d, got %d", pn, newPN)
	}

	// PACKET_NUMBER_TAG
	if packet_setting.PacketNumberIncrementBPFHandler != nil && p.connection.LocalAddr().String() == packet_setting.RELAY_ADDR {
		// Handle the change of packet number by calling the BPF handler function
		// defined by the user who knows about the specific BPF setup
		packet_setting.PacketNumberIncrementBPFHandler(int64(pn), p.connection)
	}

	return shortHeaderPacket{
		PacketNumber:         pn,
		PacketNumberLen:      pnLen,
		KeyPhase:             kp,
		StreamFrames:         pl.streamFrames,
		Frames:               pl.frames,
		Ack:                  pl.ack,
		Length:               protocol.ByteCount(len(raw)),
		DestConnID:           connID,
		IsPathMTUProbePacket: isMTUProbePacket,
	}, nil
}

// appendPacketPayload serializes the payload of a packet into the raw byte slice.
// It modifies the order of payload.frames.
func (p *packetPacker) appendPacketPayload(raw []byte, pl payload, paddingLen protocol.ByteCount, v protocol.Version) ([]byte, error) {
	payloadOffset := len(raw)
	if pl.ack != nil {
		var err error
		raw, err = pl.ack.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	if paddingLen > 0 {
		raw = append(raw, make([]byte, paddingLen)...)
	}
	// Randomize the order of the control frames.
	// This makes sure that the receiver doesn't rely on the order in which frames are packed.
	if len(pl.frames) > 1 {
		p.rand.Shuffle(len(pl.frames), func(i, j int) { pl.frames[i], pl.frames[j] = pl.frames[j], pl.frames[i] })
	}
	for _, f := range pl.frames {
		var err error
		raw, err = f.Frame.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}
	for _, f := range pl.streamFrames {
		var err error
		raw, err = f.Frame.Append(raw, v)
		if err != nil {
			return nil, err
		}
	}

	// DEBUG_TAG
	// if packet_setting.BPF_TURNED_ON {
	// 	if len(pl.frames) > 0 && len(pl.streamFrames) > 0 ||
	// 		len(pl.streamFrames) > 1 {
	// 		panic(">0")
	// 	} else {
	// 		//fmt.Println("All good")
	// 	}
	// }

	// BPF_TAG
	// STREAM_ID_TAG
	// TODO: since the stream id lenght is fixed for now quic-go thinks there is a bug / inconsistency
	// if !packet_setting.BPF_TURNED_ON { // TODO: how to handle this?
	if payloadSize := protocol.ByteCount(len(raw)-payloadOffset) - paddingLen; payloadSize != pl.length {
		fmt.Println("padding len", paddingLen)
		return nil, fmt.Errorf("PacketPacker BUG: payload size inconsistent (expected %d, got %d bytes)", pl.length, payloadSize)
	}
	// }
	return raw, nil
}

func (p *packetPacker) encryptPacket(raw []byte, sealer sealer, pn protocol.PacketNumber, payloadOffset, pnLen protocol.ByteCount) []byte {

	// NO_CRYPTO_TAG
	if crypto_turnoff.CRYPTO_TURNED_OFF {
		return raw
	}

	_ = sealer.Seal(raw[payloadOffset:payloadOffset], raw[payloadOffset:], pn, raw[:payloadOffset])
	raw = raw[:len(raw)+sealer.Overhead()]
	// apply header protection
	pnOffset := payloadOffset - pnLen
	sealer.EncryptHeader(raw[pnOffset+4:pnOffset+4+16], &raw[0], raw[pnOffset:payloadOffset])
	return raw
}

func (p *packetPacker) SetToken(token []byte) {
	p.token = token
}

// PRIO_PACKS_TAG
func (p *packetPacker) GetPriority(streamID protocol.StreamID) Priority {
	return p.connection.GetPriority(streamID)
}

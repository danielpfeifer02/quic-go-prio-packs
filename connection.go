package quic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/ackhandler"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/flowcontrol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/handshake"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/logutils"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/qerr"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/utils"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/wire"
	"github.com/danielpfeifer02/quic-go-prio-packs/logging"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/quicvarint"
	crypto_settings "golang.org/x/crypto"
)

type unpacker interface {
	UnpackLongHeader(hdr *wire.Header, rcvTime time.Time, data []byte, v protocol.Version) (*unpackedPacket, error)
	UnpackShortHeader(rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error)
}

type streamGetter interface {
	GetOrOpenReceiveStream(protocol.StreamID) (receiveStreamI, error)
	GetOrOpenSendStream(protocol.StreamID) (sendStreamI, error)
}

type streamManager interface {
	GetOrOpenSendStream(protocol.StreamID) (sendStreamI, error)
	GetOrOpenReceiveStream(protocol.StreamID) (receiveStreamI, error)
	// PRIO_PACKS_TAG
	OpenStreamWithPriority(priority_setting.Priority) (Stream, error)
	OpenStream() (Stream, error)
	// PRIO_PACKS_TAG
	OpenUniStreamWithPriority(priority_setting.Priority) (SendStream, error)
	OpenUniStream() (SendStream, error)
	// PRIO_PACKS_TAG
	OpenStreamSyncWithPriority(context.Context, priority_setting.Priority) (Stream, error)
	OpenStreamSync(context.Context) (Stream, error)
	// PRIO_PACKS_TAG
	OpenUniStreamSyncWithPriority(context.Context, priority_setting.Priority) (SendStream, error)
	OpenUniStreamSync(context.Context) (SendStream, error)
	AcceptStream(context.Context) (Stream, error)
	AcceptUniStream(context.Context) (ReceiveStream, error)
	DeleteStream(protocol.StreamID) error
	UpdateLimits(*wire.TransportParameters)
	HandleMaxStreamsFrame(*wire.MaxStreamsFrame)
	CloseWithError(error)
	ResetFor0RTT()
	UseResetMaps()

	// PRIO_PACKS_TAG
	GetPriority(StreamID) Priority

	// BPF_CC_TAG
	// RETRANSMISSION_TAG
	GetSender() *streamSender
	GetNewFlowController() *func(protocol.StreamID) flowcontrol.StreamFlowController
	AddToStreams(protocol.StreamID, SendStream)
}

type cryptoStreamHandler interface {
	StartHandshake() error
	ChangeConnectionID(protocol.ConnectionID)
	SetLargest1RTTAcked(protocol.PacketNumber) error
	SetHandshakeConfirmed()
	GetSessionTicket() ([]byte, error)
	NextEvent() handshake.Event
	DiscardInitialKeys()
	io.Closer
	ConnectionState() handshake.ConnectionState
}

type receivedPacket struct {
	buffer *packetBuffer

	remoteAddr net.Addr
	rcvTime    time.Time
	data       []byte

	ecn protocol.ECN

	info packetInfo // only valid if the contained IP address is valid
}

func (p *receivedPacket) Size() protocol.ByteCount { return protocol.ByteCount(len(p.data)) }

func (p *receivedPacket) Clone() *receivedPacket {
	return &receivedPacket{
		remoteAddr: p.remoteAddr,
		rcvTime:    p.rcvTime,
		data:       p.data,
		buffer:     p.buffer,
		ecn:        p.ecn,
		info:       p.info,
	}
}

type connRunner interface {
	Add(protocol.ConnectionID, packetHandler) bool
	GetStatelessResetToken(protocol.ConnectionID) protocol.StatelessResetToken
	Retire(protocol.ConnectionID)
	Remove(protocol.ConnectionID)
	ReplaceWithClosed([]protocol.ConnectionID, []byte)
	AddResetToken(protocol.StatelessResetToken, packetHandler)
	RemoveResetToken(protocol.StatelessResetToken)
}

type closeError struct {
	err       error
	remote    bool
	immediate bool
}

type errCloseForRecreating struct {
	nextPacketNumber protocol.PacketNumber
	nextVersion      protocol.Version
}

func (e *errCloseForRecreating) Error() string {
	return "closing connection in order to recreate it"
}

var connTracingID uint64        // to be accessed atomically
func nextConnTracingID() uint64 { return atomic.AddUint64(&connTracingID, 1) }

// A Connection is a QUIC connection
type connection struct {
	// Destination connection ID used during the handshake.
	// Used to check source connection ID on incoming packets.
	handshakeDestConnID protocol.ConnectionID
	// Set for the client. Destination connection ID used on the first Initial sent.
	origDestConnID protocol.ConnectionID
	retrySrcConnID *protocol.ConnectionID // only set for the client (and if a Retry was performed)

	srcConnIDLen int

	perspective protocol.Perspective
	version     protocol.Version
	config      *Config

	conn      sendConn
	sendQueue sender

	streamsMap      streamManager
	connIDManager   *connIDManager
	connIDGenerator *connIDGenerator

	rttStats *utils.RTTStats

	cryptoStreamManager   *cryptoStreamManager
	sentPacketHandler     ackhandler.SentPacketHandler
	receivedPacketHandler ackhandler.ReceivedPacketHandler
	retransmissionQueue   *retransmissionQueue
	framer                framer
	windowUpdateQueue     *windowUpdateQueue
	connFlowController    flowcontrol.ConnectionFlowController
	tokenStoreKey         string                    // only set for the client
	tokenGenerator        *handshake.TokenGenerator // only set for the server

	unpacker      unpacker
	frameParser   wire.FrameParser
	packer        packer
	mtuDiscoverer mtuDiscoverer // initialized when the handshake completes

	initialStream       cryptoStream
	handshakeStream     cryptoStream
	oneRTTStream        cryptoStream // only set for the server
	cryptoStreamHandler cryptoStreamHandler

	receivedPackets  chan receivedPacket
	sendingScheduled chan struct{}

	closeOnce sync.Once
	// closeChan is used to notify the run loop that it should terminate
	closeChan chan closeError

	ctx                context.Context
	ctxCancel          context.CancelCauseFunc
	handshakeCtx       context.Context
	handshakeCtxCancel context.CancelFunc

	undecryptablePackets          []receivedPacket // undecryptable packets, waiting for a change in encryption level
	undecryptablePacketsToProcess []receivedPacket

	earlyConnReadyChan chan struct{}
	sentFirstPacket    bool
	droppedInitialKeys bool
	handshakeComplete  bool
	handshakeConfirmed bool

	receivedRetry       bool
	versionNegotiated   bool
	receivedFirstPacket bool

	// the minimum of the max_idle_timeout values advertised by both endpoints
	idleTimeout  time.Duration
	creationTime time.Time
	// The idle timeout is set based on the max of the time we received the last packet...
	lastPacketReceivedTime time.Time
	// ... and the time we sent a new ack-eliciting packet after receiving a packet.
	firstAckElicitingPacketAfterIdleSentTime time.Time
	// pacingDeadline is the time when the next packet should be sent
	pacingDeadline time.Time

	peerParams *wire.TransportParameters

	timer connectionTimer
	// keepAlivePingSent stores whether a keep alive PING is in flight.
	// It is reset as soon as we receive a packet from the peer.
	keepAlivePingSent bool
	keepAliveInterval time.Duration

	datagramQueue *datagramQueue

	connStateMutex sync.Mutex
	connState      ConnectionState

	logID  string
	tracer *logging.ConnectionTracer
	logger utils.Logger

	// PACKET_NUMBER_TAG
	mutex sync.Mutex
}

var (
	_ Connection      = &connection{}
	_ EarlyConnection = &connection{}
	_ streamSender    = &connection{}
)

var newConnection = func(
	conn sendConn,
	runner connRunner,
	origDestConnID protocol.ConnectionID,
	retrySrcConnID *protocol.ConnectionID,
	clientDestConnID protocol.ConnectionID,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	statelessResetToken protocol.StatelessResetToken,
	conf *Config,
	tlsConf *tls.Config,
	tokenGenerator *handshake.TokenGenerator,
	clientAddressValidated bool,
	tracer *logging.ConnectionTracer,
	tracingID uint64,
	logger utils.Logger,
	v protocol.Version,
) quicConn {
	s := &connection{
		conn:                conn,
		config:              conf,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		tokenGenerator:      tokenGenerator,
		oneRTTStream:        newCryptoStream(),
		perspective:         protocol.PerspectiveServer,
		tracer:              tracer,
		logger:              logger,
		version:             v,

		// PACKET_NUMBER_TAG
		mutex: sync.Mutex{},
	}
	if origDestConnID.Len() > 0 {
		s.logID = origDestConnID.String()
	} else {
		s.logID = destConnID.String()
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		srcConnID,
		&clientDestConnID,
		func(connID protocol.ConnectionID) { runner.Add(connID, s) },
		runner.GetStatelessResetToken,
		runner.Remove,
		runner.Retire,
		runner.ReplaceWithClosed,
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup()
	s.ctx, s.ctxCancel = context.WithCancelCause(context.WithValue(context.Background(), ConnectionTracingKey, tracingID))
	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewAckHandler(
		0,
		getMaxPacketSize(s.conn.RemoteAddr()),
		s.rttStats,
		clientAddressValidated,
		s.conn.capabilities().ECN,
		s.perspective,
		s.tracer,
		s.logger,
	)

	// BPF_CC_TAG
	s.sentPacketHandler.SetPeerIsSendServer(conn.RemoteAddr().String() == packet_setting.SERVER_ADDR)
	s.sentPacketHandler.SetConnection(s)

	s.mtuDiscoverer = newMTUDiscoverer(s.rttStats, getMaxPacketSize(s.conn.RemoteAddr()), s.sentPacketHandler.SetMaxDatagramSize)
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiLocal:   protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiRemote:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:         protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                  protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                  s.config.MaxIdleTimeout,
		MaxBidiStreamNum:                protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                 protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                     protocol.MaxAckDelayInclGranularity,
		AckDelayExponent:                protocol.AckDelayExponent,
		DisableActiveMigration:          true,
		StatelessResetToken:             &statelessResetToken,
		OriginalDestinationConnectionID: origDestConnID,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/danielpfeifer02/quic-go-prio-packs/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
		RetrySourceConnectionID:   retrySrcConnID,
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.tracer != nil && s.tracer.SentTransportParameters != nil {
		s.tracer.SentTransportParameters(params)
	}
	cs := handshake.NewCryptoSetupServer(
		clientDestConnID,
		conn.LocalAddr(),
		conn.RemoteAddr(),
		params,
		tlsConf,
		conf.Allow0RTT,
		s.rttStats,
		tracer,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.packer = newPacketPacker(s, srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.cryptoStreamManager = newCryptoStreamManager(cs, s.initialStream, s.handshakeStream, s.oneRTTStream)
	return s
}

// BPF_MAP_TAG
func (s *connection) GetDestConnID(stream Stream) protocol.ConnectionID {
	return s.connIDManager.Get(s.GetPriority(stream.StreamID()))
}

// RTT_STATS_TAG
func (s *connection) GetRTTStats() RTTStatistics {
	stats := s.rttStats
	statistics := RTTStatistics{
		MinRTT:      stats.MinRTT(),
		LatestRTT:   stats.LatestRTT(),
		SmoothedRTT: stats.SmoothedRTT(),
		RTTVariance: stats.MeanDeviation(),
		MaxAckDelay: stats.MaxAckDelay(),
	}
	return statistics
}

// declare this as a variable, such that we can it mock it in the tests
var newClientConnection = func(
	conn sendConn,
	runner connRunner,
	destConnID protocol.ConnectionID,
	srcConnID protocol.ConnectionID,
	connIDGenerator ConnectionIDGenerator,
	conf *Config,
	tlsConf *tls.Config,
	initialPacketNumber protocol.PacketNumber,
	enable0RTT bool,
	hasNegotiatedVersion bool,
	tracer *logging.ConnectionTracer,
	tracingID uint64,
	logger utils.Logger,
	v protocol.Version,
) quicConn {
	s := &connection{
		conn:                conn,
		config:              conf,
		origDestConnID:      destConnID,
		handshakeDestConnID: destConnID,
		srcConnIDLen:        srcConnID.Len(),
		perspective:         protocol.PerspectiveClient,
		logID:               destConnID.String(),
		logger:              logger,
		tracer:              tracer,
		versionNegotiated:   hasNegotiatedVersion,
		version:             v,
	}
	s.connIDManager = newConnIDManager(
		destConnID,
		func(token protocol.StatelessResetToken) { runner.AddResetToken(token, s) },
		runner.RemoveResetToken,
		s.queueControlFrame,
	)
	s.connIDGenerator = newConnIDGenerator(
		srcConnID,
		nil,
		func(connID protocol.ConnectionID) { runner.Add(connID, s) },
		runner.GetStatelessResetToken,
		runner.Remove,
		runner.Retire,
		runner.ReplaceWithClosed,
		s.queueControlFrame,
		connIDGenerator,
	)
	s.preSetup()
	s.ctx, s.ctxCancel = context.WithCancelCause(context.WithValue(context.Background(), ConnectionTracingKey, tracingID))
	s.sentPacketHandler, s.receivedPacketHandler = ackhandler.NewAckHandler(
		initialPacketNumber,
		getMaxPacketSize(s.conn.RemoteAddr()),
		s.rttStats,
		false, // has no effect
		s.conn.capabilities().ECN,
		s.perspective,
		s.tracer,
		s.logger,
	)

	// BPF_CC_TAG
	s.sentPacketHandler.SetPeerIsSendServer(conn.RemoteAddr().String() == packet_setting.SERVER_ADDR)

	s.mtuDiscoverer = newMTUDiscoverer(s.rttStats, getMaxPacketSize(s.conn.RemoteAddr()), s.sentPacketHandler.SetMaxDatagramSize)
	oneRTTStream := newCryptoStream()
	params := &wire.TransportParameters{
		InitialMaxStreamDataBidiRemote: protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataBidiLocal:  protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxStreamDataUni:        protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		InitialMaxData:                 protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		MaxIdleTimeout:                 s.config.MaxIdleTimeout,
		MaxBidiStreamNum:               protocol.StreamNum(s.config.MaxIncomingStreams),
		MaxUniStreamNum:                protocol.StreamNum(s.config.MaxIncomingUniStreams),
		MaxAckDelay:                    protocol.MaxAckDelayInclGranularity,
		AckDelayExponent:               protocol.AckDelayExponent,
		DisableActiveMigration:         true,
		// For interoperability with quic-go versions before May 2023, this value must be set to a value
		// different from protocol.DefaultActiveConnectionIDLimit.
		// If set to the default value, it will be omitted from the transport parameters, which will make
		// old quic-go versions interpret it as 0, instead of the default value of 2.
		// See https://github.com/danielpfeifer02/quic-go-prio-packs/pull/3806.
		ActiveConnectionIDLimit:   protocol.MaxActiveConnectionIDs,
		InitialSourceConnectionID: srcConnID,
	}
	if s.config.EnableDatagrams {
		params.MaxDatagramFrameSize = wire.MaxDatagramSize
	} else {
		params.MaxDatagramFrameSize = protocol.InvalidByteCount
	}
	if s.tracer != nil && s.tracer.SentTransportParameters != nil {
		s.tracer.SentTransportParameters(params)
	}
	cs := handshake.NewCryptoSetupClient(
		destConnID,
		params,
		tlsConf,
		enable0RTT,
		s.rttStats,
		tracer,
		logger,
		s.version,
	)
	s.cryptoStreamHandler = cs
	s.cryptoStreamManager = newCryptoStreamManager(cs, s.initialStream, s.handshakeStream, oneRTTStream)
	s.unpacker = newPacketUnpacker(cs, s.srcConnIDLen)
	s.packer = newPacketPacker(s, srcConnID, s.connIDManager.Get, s.initialStream, s.handshakeStream, s.sentPacketHandler, s.retransmissionQueue, cs, s.framer, s.receivedPacketHandler, s.datagramQueue, s.perspective)
	if len(tlsConf.ServerName) > 0 {
		s.tokenStoreKey = tlsConf.ServerName
	} else {
		s.tokenStoreKey = conn.RemoteAddr().String()
	}
	if s.config.TokenStore != nil {
		if token := s.config.TokenStore.Pop(s.tokenStoreKey); token != nil {
			s.packer.SetToken(token.data)
		}
	}
	return s
}

func (s *connection) preSetup() {
	s.initialStream = newCryptoStream()
	s.handshakeStream = newCryptoStream()
	s.sendQueue = newSendQueue(s.conn)
	s.retransmissionQueue = newRetransmissionQueue()
	s.frameParser = *wire.NewFrameParser(s.config.EnableDatagrams)
	s.rttStats = &utils.RTTStats{}
	s.connFlowController = flowcontrol.NewConnectionFlowController(
		protocol.ByteCount(s.config.InitialConnectionReceiveWindow),
		protocol.ByteCount(s.config.MaxConnectionReceiveWindow),
		s.onHasConnectionWindowUpdate,
		func(size protocol.ByteCount) bool {
			if s.config.AllowConnectionWindowIncrease == nil {
				return true
			}
			return s.config.AllowConnectionWindowIncrease(s, uint64(size))
		},
		s.rttStats,
		s.logger,
	)
	s.earlyConnReadyChan = make(chan struct{})
	s.streamsMap = newStreamsMap(
		s,
		s.newFlowController,
		uint64(s.config.MaxIncomingStreams),
		uint64(s.config.MaxIncomingUniStreams),
		s.perspective,
	)

	// RETRANSMISSION_TAG
	// DEBUG_TAG
	s.framer = newFramer(s.streamsMap, s)
	s.receivedPackets = make(chan receivedPacket, protocol.MaxConnUnprocessedPackets)
	s.closeChan = make(chan closeError, 1)
	s.sendingScheduled = make(chan struct{}, 1)
	s.handshakeCtx, s.handshakeCtxCancel = context.WithCancel(context.Background())

	now := time.Now()
	s.lastPacketReceivedTime = now
	s.creationTime = now

	s.windowUpdateQueue = newWindowUpdateQueue(s.streamsMap, s.connFlowController, s.framer.QueueControlFrame)
	s.datagramQueue = newDatagramQueue(s.scheduleSending, s.logger)
	s.connState.Version = s.version
}

// run the connection main loop
func (s *connection) run() error {
	var closeErr closeError
	defer func() {
		s.ctxCancel(closeErr.err)
	}()

	s.timer = *newTimer()

	if err := s.cryptoStreamHandler.StartHandshake(); err != nil {
		return err
	}
	if err := s.handleHandshakeEvents(); err != nil {
		return err
	}
	go func() {
		if err := s.sendQueue.Run(); err != nil {
			s.destroyImpl(err)
		}
	}()

	if s.perspective == protocol.PerspectiveClient {
		s.scheduleSending() // so the ClientHello actually gets sent
	}

	var sendQueueAvailable <-chan struct{}

runLoop:
	for {
		// Close immediately if requested
		select {
		case closeErr = <-s.closeChan:
			break runLoop
		default:
		}

		s.maybeResetTimer()

		var processedUndecryptablePacket bool
		if len(s.undecryptablePacketsToProcess) > 0 {
			queue := s.undecryptablePacketsToProcess
			s.undecryptablePacketsToProcess = nil
			for _, p := range queue {
				if processed := s.handlePacketImpl(p); processed {
					processedUndecryptablePacket = true
				}
				// Don't set timers and send packets if the packet made us close the connection.
				select {
				case closeErr = <-s.closeChan:
					break runLoop
				default:
				}
			}
		}
		// If we processed any undecryptable packets, jump to the resetting of the timers directly.
		if !processedUndecryptablePacket {
			select {
			case closeErr = <-s.closeChan:
				break runLoop
			case <-s.timer.Chan():
				s.timer.SetRead()
				// We do all the interesting stuff after the switch statement, so
				// nothing to see here.
			case <-s.sendingScheduled:
				// We do all the interesting stuff after the switch statement, so
				// nothing to see here.
			case <-sendQueueAvailable:
			case firstPacket := <-s.receivedPackets:
				wasProcessed := s.handlePacketImpl(firstPacket)
				// Don't set timers and send packets if the packet made us close the connection.
				select {
				case closeErr = <-s.closeChan:
					break runLoop
				default:
				}
				if s.handshakeComplete {
					// Now process all packets in the receivedPackets channel.
					// Limit the number of packets to the length of the receivedPackets channel,
					// so we eventually get a chance to send out an ACK when receiving a lot of packets.
					numPackets := len(s.receivedPackets)
				receiveLoop:
					for i := 0; i < numPackets; i++ {
						select {
						case p := <-s.receivedPackets:
							if processed := s.handlePacketImpl(p); processed {
								wasProcessed = true
							}
							select {
							case closeErr = <-s.closeChan:
								break runLoop
							default:
							}
						default:
							break receiveLoop
						}
					}
				}
				// Only reset the timers if this packet was actually processed.
				// This avoids modifying any state when handling undecryptable packets,
				// which could be injected by an attacker.
				if !wasProcessed {
					continue
				}
			}
		}

		now := time.Now()
		if timeout := s.sentPacketHandler.GetLossDetectionTimeout(); !timeout.IsZero() && timeout.Before(now) {
			// This could cause packets to be retransmitted.
			// Check it before trying to send packets.
			if err := s.sentPacketHandler.OnLossDetectionTimeout(); err != nil {
				s.closeLocal(err)
			}
		}

		if keepAliveTime := s.nextKeepAliveTime(); !keepAliveTime.IsZero() && !now.Before(keepAliveTime) {
			// send a PING frame since there is no activity in the connection
			s.logger.Debugf("Sending a keep-alive PING to keep the connection alive.")
			s.framer.QueueControlFrame(&wire.PingFrame{})
			s.keepAlivePingSent = true
		} else if !s.handshakeComplete && now.Sub(s.creationTime) >= s.config.handshakeTimeout() {
			s.destroyImpl(qerr.ErrHandshakeTimeout)
			continue
		} else {
			idleTimeoutStartTime := s.idleTimeoutStartTime()
			if (!s.handshakeComplete && now.Sub(idleTimeoutStartTime) >= s.config.HandshakeIdleTimeout) ||
				(s.handshakeComplete && now.After(s.nextIdleTimeoutTime())) {
				s.destroyImpl(qerr.ErrIdleTimeout)
				continue
			}
		}

		if s.sendQueue.WouldBlock() {
			// The send queue is still busy sending out packets.
			// Wait until there's space to enqueue new packets.
			sendQueueAvailable = s.sendQueue.Available()
			continue
		}
		if err := s.triggerSending(now); err != nil {
			s.closeLocal(err)
		}
		if s.sendQueue.WouldBlock() {
			sendQueueAvailable = s.sendQueue.Available()
		} else {
			sendQueueAvailable = nil
		}
	}

	s.cryptoStreamHandler.Close()
	s.sendQueue.Close() // close the send queue before sending the CONNECTION_CLOSE
	s.handleCloseError(&closeErr)
	if s.tracer != nil && s.tracer.Close != nil {
		if e := (&errCloseForRecreating{}); !errors.As(closeErr.err, &e) {
			s.tracer.Close()
		}
	}
	s.logger.Infof("Connection %s closed.", s.logID)
	s.timer.Stop()
	return closeErr.err
}

// blocks until the early connection can be used
func (s *connection) earlyConnReady() <-chan struct{} {
	return s.earlyConnReadyChan
}

func (s *connection) HandshakeComplete() <-chan struct{} {
	return s.handshakeCtx.Done()
}

func (s *connection) Context() context.Context {
	return s.ctx
}

func (s *connection) supportsDatagrams() bool {
	return s.peerParams.MaxDatagramFrameSize > 0
}

func (s *connection) ConnectionState() ConnectionState {
	s.connStateMutex.Lock()
	defer s.connStateMutex.Unlock()
	cs := s.cryptoStreamHandler.ConnectionState()
	s.connState.TLS = cs.ConnectionState
	s.connState.Used0RTT = cs.Used0RTT
	s.connState.GSO = s.conn.capabilities().GSO
	return s.connState
}

// Time when the connection should time out
func (s *connection) nextIdleTimeoutTime() time.Time {
	idleTimeout := max(s.idleTimeout, s.rttStats.PTO(true)*3)
	return s.idleTimeoutStartTime().Add(idleTimeout)
}

// Time when the next keep-alive packet should be sent.
// It returns a zero time if no keep-alive should be sent.
func (s *connection) nextKeepAliveTime() time.Time {
	if s.config.KeepAlivePeriod == 0 || s.keepAlivePingSent || !s.firstAckElicitingPacketAfterIdleSentTime.IsZero() {
		return time.Time{}
	}
	keepAliveInterval := max(s.keepAliveInterval, s.rttStats.PTO(true)*3/2)
	return s.lastPacketReceivedTime.Add(keepAliveInterval)
}

func (s *connection) maybeResetTimer() {
	var deadline time.Time
	if !s.handshakeComplete {
		deadline = utils.MinTime(
			s.creationTime.Add(s.config.handshakeTimeout()),
			s.idleTimeoutStartTime().Add(s.config.HandshakeIdleTimeout),
		)
	} else {
		if keepAliveTime := s.nextKeepAliveTime(); !keepAliveTime.IsZero() {
			deadline = keepAliveTime
		} else {
			deadline = s.nextIdleTimeoutTime()
		}
	}

	s.timer.SetTimer(
		deadline,
		s.receivedPacketHandler.GetAlarmTimeout(),
		s.sentPacketHandler.GetLossDetectionTimeout(),
		s.pacingDeadline,
	)
}

func (s *connection) idleTimeoutStartTime() time.Time {
	return utils.MaxTime(s.lastPacketReceivedTime, s.firstAckElicitingPacketAfterIdleSentTime)
}

func (s *connection) handleHandshakeComplete() error {
	defer s.handshakeCtxCancel()
	// Once the handshake completes, we have derived 1-RTT keys.
	// There's no point in queueing undecryptable packets for later decryption anymore.
	s.undecryptablePackets = nil

	s.connIDManager.SetHandshakeComplete()
	s.connIDGenerator.SetHandshakeComplete()

	if s.tracer != nil && s.tracer.ChoseALPN != nil {
		s.tracer.ChoseALPN(s.cryptoStreamHandler.ConnectionState().NegotiatedProtocol)
	}

	// The server applies transport parameters right away, but the client side has to wait for handshake completion.
	// During a 0-RTT connection, the client is only allowed to use the new transport parameters for 1-RTT packets.
	if s.perspective == protocol.PerspectiveClient {
		s.applyTransportParameters()
		return nil
	}

	// All these only apply to the server side.
	if err := s.handleHandshakeConfirmed(); err != nil {
		return err
	}

	ticket, err := s.cryptoStreamHandler.GetSessionTicket()
	if err != nil {
		return err
	}
	if ticket != nil { // may be nil if session tickets are disabled via tls.Config.SessionTicketsDisabled
		s.oneRTTStream.Write(ticket)
		for s.oneRTTStream.HasData() {
			s.queueControlFrame(s.oneRTTStream.PopCryptoFrame(protocol.MaxPostHandshakeCryptoFrameSize))
		}
	}
	token, err := s.tokenGenerator.NewToken(s.conn.RemoteAddr())
	if err != nil {
		return err
	}
	s.queueControlFrame(&wire.NewTokenFrame{Token: token})
	s.queueControlFrame(&wire.HandshakeDoneFrame{})
	return nil
}

func (s *connection) handleHandshakeConfirmed() error {
	if err := s.dropEncryptionLevel(protocol.EncryptionHandshake); err != nil {
		return err
	}

	s.handshakeConfirmed = true
	s.sentPacketHandler.SetHandshakeConfirmed()
	s.cryptoStreamHandler.SetHandshakeConfirmed()

	if !s.config.DisablePathMTUDiscovery && s.conn.capabilities().DF {
		maxPacketSize := s.peerParams.MaxUDPPayloadSize
		if maxPacketSize == 0 {
			maxPacketSize = protocol.MaxByteCount
		}
		s.mtuDiscoverer.Start(min(maxPacketSize, protocol.MaxPacketBufferSize))
	}
	return nil
}

func (s *connection) handlePacketImpl(rp receivedPacket) bool {
	s.sentPacketHandler.ReceivedBytes(rp.Size())

	if wire.IsVersionNegotiationPacket(rp.data) {
		s.handleVersionNegotiationPacket(rp)
		return false
	}

	var counter uint8
	var lastConnID protocol.ConnectionID
	var processed bool
	data := rp.data
	p := rp
	for len(data) > 0 {
		var destConnID protocol.ConnectionID
		if counter > 0 {
			p = *(p.Clone())
			p.data = data

			var err error
			destConnID, err = wire.ParseConnectionID(p.data, s.srcConnIDLen)
			if err != nil {
				if s.tracer != nil && s.tracer.DroppedPacket != nil {
					s.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropHeaderParseError)
				}
				s.logger.Debugf("error parsing packet, couldn't parse connection ID: %s", err)
				break
			}
			if destConnID != lastConnID {
				if s.tracer != nil && s.tracer.DroppedPacket != nil {
					s.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropUnknownConnectionID)
				}
				s.logger.Debugf("coalesced packet has different destination connection ID: %s, expected %s", destConnID, lastConnID)
				break
			}
		}

		if wire.IsLongHeaderPacket(p.data[0]) {
			hdr, packetData, rest, err := wire.ParsePacket(p.data)
			if err != nil {
				if s.tracer != nil && s.tracer.DroppedPacket != nil {
					dropReason := logging.PacketDropHeaderParseError
					if err == wire.ErrUnsupportedVersion {
						dropReason = logging.PacketDropUnsupportedVersion
					}
					s.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), dropReason)
				}
				s.logger.Debugf("error parsing packet: %s", err)
				break
			}
			lastConnID = hdr.DestConnectionID

			if hdr.Version != s.version {
				if s.tracer != nil && s.tracer.DroppedPacket != nil {
					s.tracer.DroppedPacket(logging.PacketTypeFromHeader(hdr), protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedVersion)
				}
				s.logger.Debugf("Dropping packet with version %x. Expected %x.", hdr.Version, s.version)
				break
			}

			if counter > 0 {
				p.buffer.Split()
			}
			counter++

			// only log if this actually a coalesced packet
			if s.logger.Debug() && (counter > 1 || len(rest) > 0) {
				s.logger.Debugf("Parsed a coalesced packet. Part %d: %d bytes. Remaining: %d bytes.", counter, len(packetData), len(rest))
			}

			p.data = packetData

			if wasProcessed := s.handleLongHeaderPacket(p, hdr); wasProcessed {
				processed = true
			}
			data = rest

			// fmt.Println("HandlePacket: Long Header")
		} else {
			// fmt.Println("HandlePacket: Short Header")
			if counter > 0 {
				p.buffer.Split()
			}
			processed = s.handleShortHeaderPacket(p, destConnID)
			break
		}
	}

	p.buffer.MaybeRelease()
	return processed
}

// BPF_CC_TAG
// CACHING_TAG
// RETRANSMISSION_TAG
func (s *connection) parseBPFSavedRawData(data []byte) ([]packet_setting.GeneralFrame, []packet_setting.StreamFrame, error) {
	frames := make([]packet_setting.GeneralFrame, 0)
	stream_frames := make([]packet_setting.StreamFrame, 0)

	// Apparently parsing the frame causes some wrong internal state in the connection
	// that's why we use a throwaway connection
	// To avoid this overhead one could use the parsing of the frames that happens anyway
	// later in handleFrames but this was easier to work with / debug if it was separated
	// TODONOW: combine with other parsing
	// TODONOW: is any state from previous packets needed for decoding
	// TODONOW: i.e. is a throwaway connection not 100% correct?
	throwaway_parser := *wire.NewFrameParser(s.config.EnableDatagrams)

	// For now only one frame per packet. This is a simplification and can be changed later to "for len(data) > 0"
	l, frame, err := throwaway_parser.ParseNext(data, protocol.Encryption1RTT, s.version)
	if err != nil {
		panic(err)
	}
	data = data[l:]

	if frame == nil {
		return frames, stream_frames, nil // TODO: how to handle correctly
	}

	if stream_frame, ok := frame.(*wire.StreamFrame); ok {
		ps_sf := packet_setting.StreamFrame{
			StreamID:       stream_frame.StreamID,
			Offset:         stream_frame.Offset,
			Data:           stream_frame.Data,
			Fin:            stream_frame.Fin,
			DataLenPresent: stream_frame.DataLenPresent,
		}
		stream_frames = append(stream_frames, ps_sf)
	} else if _, ok := frame.(*wire.DatagramFrame); ok {
		return nil, nil, errors.New("Datagram")
	} else {
		fmt.Println("Omitting some frame. For now only stream frames are supported", reflect.TypeOf(frame)) // TODONOW: handle all frames that can occur
		return frames, stream_frames, nil                                                                   // TODO handle correctly
	}
	if len(data) > 0 {
		panic("Not all data was consumed")
	}
	// }
	return frames, stream_frames, nil
}

// EBPF_CRYPTO_TAG
// This function allows the relay go program to start the generation of tls keys, nonces and xor masks
// and stores them using a relay-developer defined function.
// This function does "pre-generation", meaning that it generates the same keys, nonces and masks as the
// normal crypto handling would but in a separate manner (for now).
func (s *connection) Start1RTTCryptoBitstreamStorage() {
	pack_unpacker := s.unpacker.(*packetUnpacker)

	crypto_setup := pack_unpacker.cs
	opener, err := crypto_setup.Get1RTTOpener()
	if err != nil {
		panic(err)
	}

	// We need to work with a copy of the opener, because the original opener is used by the connection
	// This opener is of type updatableAEAD
	updatable_aead := opener.(*handshake.UpdatableAEAD)
	opener_copy := handshake.GetCopyOfUpdatableAEAD(updatable_aead) // TODO: this is likely not a completely correct copy -> how to fix?

	for i := 0; i < 10000; i++ { // TODO: how often? infinite loop until some condition to continuously generate keys?
		pn := protocol.PacketNumber(i)
		opener_copy.Start1RTTCryptoBitstreamStorage(pn)

		if crypto_settings.PotentiallTriggerCryptoGarbageCollector != nil {
			go crypto_settings.PotentiallTriggerCryptoGarbageCollector() // TODO: generating A LOT of threads?
		}
	}

}

func (s *connection) handleShortHeaderPacket(p receivedPacket, destConnID protocol.ConnectionID) bool {
	var wasQueued bool

	defer func() {
		// Put back the packet buffer if the packet wasn't queued for later decryption.
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	pn, pnLen, keyPhase, data, err := s.unpacker.UnpackShortHeader(p.rcvTime, p.data)
	if err != nil {
		wasQueued = s.handleUnpackError(err, p, logging.PacketType1RTT)
		return false
	}

	// CACHING_TAG
	// RETRANSMISSION_TAG
	// TODONOW: add storage of server_pn to data mapping here for retransmission
	// TODONOW: make sure only relay does this
	if packet_setting.StoreServerPacket != nil && s.RemoteAddr().String() == packet_setting.SERVER_ADDR {
		data_dup := make([]byte, len(data))
		copy(data_dup, data)

		ts := p.rcvTime.UnixNano()

		packet_setting.StoreServerPacket(int64(pn), ts, data_dup, s)
	}

	// BPF_CC_TAG
	if packet_setting.IS_CLIENT && packet_setting.ReceivedPacketAtTimestampHandler != nil { //&& s.LocalAddr().String() == packet_setting.RELAY_OOB_ADDR {
		packet_setting.ReceivedPacketAtTimestampHandler(int64(pn), p.rcvTime.UnixNano(), s)
	}

	if s.logger.Debug() {
		s.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, 1-RTT", pn, p.Size(), destConnID)
		wire.LogShortHeader(s.logger, destConnID, pn, pnLen, keyPhase)
	}

	if s.receivedPacketHandler.IsPotentiallyDuplicate(pn, protocol.Encryption1RTT) {
		s.logger.Debugf("Dropping (potentially) duplicate packet.")
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketType1RTT, pn, p.Size(), logging.PacketDropDuplicate)
		}
		return false
	}

	var log func([]logging.Frame)
	if s.tracer != nil && s.tracer.ReceivedShortHeaderPacket != nil {
		log = func(frames []logging.Frame) {
			s.tracer.ReceivedShortHeaderPacket(
				&logging.ShortHeader{
					DestConnectionID: destConnID,
					PacketNumber:     pn,
					PacketNumberLen:  pnLen,
					KeyPhase:         keyPhase,
				},
				p.Size(),
				p.ecn,
				frames,
			)
		}
	}
	if err := s.handleUnpackedShortHeaderPacket(destConnID, pn, data, p.ecn, p.rcvTime, log); err != nil {
		s.closeLocal(err)
		return false
	}
	return true
}

func (s *connection) handleLongHeaderPacket(p receivedPacket, hdr *wire.Header) bool /* was the packet successfully processed */ {
	var wasQueued bool

	defer func() {
		// Put back the packet buffer if the packet wasn't queued for later decryption.
		if !wasQueued {
			p.buffer.Decrement()
		}
	}()

	if hdr.Type == protocol.PacketTypeRetry {
		return s.handleRetryPacket(hdr, p.data, p.rcvTime)
	}

	// The server can change the source connection ID with the first Handshake packet.
	// After this, all packets with a different source connection have to be ignored.
	if s.receivedFirstPacket && hdr.Type == protocol.PacketTypeInitial && hdr.SrcConnectionID != s.handshakeDestConnID {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeInitial, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnknownConnectionID)
		}
		s.logger.Debugf("Dropping Initial packet (%d bytes) with unexpected source connection ID: %s (expected %s)", p.Size(), hdr.SrcConnectionID, s.handshakeDestConnID)
		return false
	}
	// drop 0-RTT packets, if we are a client
	if s.perspective == protocol.PerspectiveClient && hdr.Type == protocol.PacketType0RTT {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketType0RTT, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropKeyUnavailable)
		}
		return false
	}

	packet, err := s.unpacker.UnpackLongHeader(hdr, p.rcvTime, p.data, s.version)
	if err != nil {
		wasQueued = s.handleUnpackError(err, p, logging.PacketTypeFromHeader(hdr))
		return false
	}

	if s.logger.Debug() {
		s.logger.Debugf("<- Reading packet %d (%d bytes) for connection %s, %s", packet.hdr.PacketNumber, p.Size(), hdr.DestConnectionID, packet.encryptionLevel)
		packet.hdr.Log(s.logger)
	}

	if pn := packet.hdr.PacketNumber; s.receivedPacketHandler.IsPotentiallyDuplicate(pn, packet.encryptionLevel) {
		s.logger.Debugf("Dropping (potentially) duplicate packet.")
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeFromHeader(hdr), pn, p.Size(), logging.PacketDropDuplicate)
		}
		return false
	}

	if err := s.handleUnpackedLongHeaderPacket(packet, p.ecn, p.rcvTime, p.Size()); err != nil {
		s.closeLocal(err)
		return false
	}
	return true
}

func (s *connection) handleUnpackError(err error, p receivedPacket, pt logging.PacketType) (wasQueued bool) {
	switch err {
	case handshake.ErrKeysDropped:
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(pt, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropKeyUnavailable)
		}
		s.logger.Debugf("Dropping %s packet (%d bytes) because we already dropped the keys.", pt, p.Size())
	case handshake.ErrKeysNotYetAvailable:
		// Sealer for this encryption level not yet available.
		// Try again later.
		s.tryQueueingUndecryptablePacket(p, pt)
		return true
	case wire.ErrInvalidReservedBits:
		s.closeLocal(&qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: err.Error(),
		})
	case handshake.ErrDecryptionFailed:
		// This might be a packet injected by an attacker. Drop it.
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(pt, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropPayloadDecryptError)
		}
		s.logger.Debugf("Dropping %s packet (%d bytes) that could not be unpacked. Error: %s", pt, p.Size(), err)
	default:
		var headerErr *headerParseError
		if errors.As(err, &headerErr) {
			// This might be a packet injected by an attacker. Drop it.
			if s.tracer != nil && s.tracer.DroppedPacket != nil {
				s.tracer.DroppedPacket(pt, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropHeaderParseError)
			}
			s.logger.Debugf("Dropping %s packet (%d bytes) for which we couldn't unpack the header. Error: %s", pt, p.Size(), err)
		} else {
			// This is an error returned by the AEAD (other than ErrDecryptionFailed).
			// For example, a PROTOCOL_VIOLATION due to key updates.
			s.closeLocal(err)
		}
	}
	return false
}

func (s *connection) handleRetryPacket(hdr *wire.Header, data []byte, rcvTime time.Time) bool /* was this a valid Retry */ {
	if s.perspective == protocol.PerspectiveServer {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedPacket)
		}
		s.logger.Debugf("Ignoring Retry.")
		return false
	}
	if s.receivedFirstPacket {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedPacket)
		}
		s.logger.Debugf("Ignoring Retry, since we already received a packet.")
		return false
	}
	// PRIO_PACKS_TAG
	destConnID := s.connIDManager.Get(priority_setting.PrioRetryPacket)
	if hdr.SrcConnectionID == destConnID {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropUnexpectedPacket)
		}
		s.logger.Debugf("Ignoring Retry, since the server didn't change the Source Connection ID.")
		return false
	}
	// If a token is already set, this means that we already received a Retry from the server.
	// Ignore this Retry packet.
	if s.receivedRetry {
		s.logger.Debugf("Ignoring Retry, since a Retry was already received.")
		return false
	}

	tag := handshake.GetRetryIntegrityTag(data[:len(data)-16], destConnID, hdr.Version)
	if !bytes.Equal(data[len(data)-16:], tag[:]) {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeRetry, protocol.InvalidPacketNumber, protocol.ByteCount(len(data)), logging.PacketDropPayloadDecryptError)
		}
		s.logger.Debugf("Ignoring spoofed Retry. Integrity Tag doesn't match.")
		return false
	}

	if s.logger.Debug() {
		s.logger.Debugf("<- Received Retry:")
		(&wire.ExtendedHeader{Header: *hdr}).Log(s.logger)
		s.logger.Debugf("Switching destination connection ID to: %s", hdr.SrcConnectionID)
	}
	if s.tracer != nil && s.tracer.ReceivedRetry != nil {
		s.tracer.ReceivedRetry(hdr)
	}
	newDestConnID := hdr.SrcConnectionID
	s.receivedRetry = true
	if err := s.sentPacketHandler.ResetForRetry(rcvTime); err != nil {
		s.closeLocal(err)
		return false
	}
	s.handshakeDestConnID = newDestConnID
	s.retrySrcConnID = &newDestConnID
	s.cryptoStreamHandler.ChangeConnectionID(newDestConnID)
	s.packer.SetToken(hdr.Token)
	s.connIDManager.ChangeInitialConnID(newDestConnID)
	s.scheduleSending()
	return true
}

func (s *connection) handleVersionNegotiationPacket(p receivedPacket) {
	if s.perspective == protocol.PerspectiveServer || // servers never receive version negotiation packets
		s.receivedFirstPacket || s.versionNegotiated { // ignore delayed / duplicated version negotiation packets
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeVersionNegotiation, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnexpectedPacket)
		}
		return
	}

	src, dest, supportedVersions, err := wire.ParseVersionNegotiationPacket(p.data)
	if err != nil {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			s.tracer.DroppedPacket(logging.PacketTypeVersionNegotiation, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropHeaderParseError)
		}
		s.logger.Debugf("Error parsing Version Negotiation packet: %s", err)
		return
	}

	for _, v := range supportedVersions {
		if v == s.version {
			if s.tracer != nil && s.tracer.DroppedPacket != nil {
				s.tracer.DroppedPacket(logging.PacketTypeVersionNegotiation, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropUnexpectedVersion)
			}
			// The Version Negotiation packet contains the version that we offered.
			// This might be a packet sent by an attacker, or it was corrupted.
			return
		}
	}

	s.logger.Infof("Received a Version Negotiation packet. Supported Versions: %s", supportedVersions)
	if s.tracer != nil && s.tracer.ReceivedVersionNegotiationPacket != nil {
		s.tracer.ReceivedVersionNegotiationPacket(dest, src, supportedVersions)
	}
	newVersion, ok := protocol.ChooseSupportedVersion(s.config.Versions, supportedVersions)
	if !ok {
		s.destroyImpl(&VersionNegotiationError{
			Ours:   s.config.Versions,
			Theirs: supportedVersions,
		})
		s.logger.Infof("No compatible QUIC version found.")
		return
	}
	if s.tracer != nil && s.tracer.NegotiatedVersion != nil {
		s.tracer.NegotiatedVersion(newVersion, s.config.Versions, supportedVersions)
	}

	s.logger.Infof("Switching to QUIC version %s.", newVersion)
	nextPN, _ := s.sentPacketHandler.PeekPacketNumber(protocol.EncryptionInitial)
	s.destroyImpl(&errCloseForRecreating{
		nextPacketNumber: nextPN,
		nextVersion:      newVersion,
	})
}

func (s *connection) handleUnpackedLongHeaderPacket(
	packet *unpackedPacket,
	ecn protocol.ECN,
	rcvTime time.Time,
	packetSize protocol.ByteCount, // only for logging
) error {
	if !s.receivedFirstPacket {
		s.receivedFirstPacket = true
		if !s.versionNegotiated && s.tracer != nil && s.tracer.NegotiatedVersion != nil {
			var clientVersions, serverVersions []protocol.Version
			switch s.perspective {
			case protocol.PerspectiveClient:
				clientVersions = s.config.Versions
			case protocol.PerspectiveServer:
				serverVersions = s.config.Versions
			}
			s.tracer.NegotiatedVersion(s.version, clientVersions, serverVersions)
		}
		// The server can change the source connection ID with the first Handshake packet.
		if s.perspective == protocol.PerspectiveClient && packet.hdr.SrcConnectionID != s.handshakeDestConnID {
			cid := packet.hdr.SrcConnectionID
			s.logger.Debugf("Received first packet. Switching destination connection ID to: %s", cid)
			s.handshakeDestConnID = cid
			s.connIDManager.ChangeInitialConnID(cid)
		}
		// We create the connection as soon as we receive the first packet from the client.
		// We do that before authenticating the packet.
		// That means that if the source connection ID was corrupted,
		// we might have created a connection with an incorrect source connection ID.
		// Once we authenticate the first packet, we need to update it.
		if s.perspective == protocol.PerspectiveServer {
			if packet.hdr.SrcConnectionID != s.handshakeDestConnID {
				s.handshakeDestConnID = packet.hdr.SrcConnectionID
				s.connIDManager.ChangeInitialConnID(packet.hdr.SrcConnectionID)
			}
			if s.tracer != nil && s.tracer.StartedConnection != nil {
				s.tracer.StartedConnection(
					s.conn.LocalAddr(),
					s.conn.RemoteAddr(),
					packet.hdr.SrcConnectionID,
					packet.hdr.DestConnectionID,
				)
			}
		}
	}

	if s.perspective == protocol.PerspectiveServer && packet.encryptionLevel == protocol.EncryptionHandshake &&
		!s.droppedInitialKeys {
		// On the server side, Initial keys are dropped as soon as the first Handshake packet is received.
		// See Section 4.9.1 of RFC 9001.
		if err := s.dropEncryptionLevel(protocol.EncryptionInitial); err != nil {
			return err
		}
	}

	s.lastPacketReceivedTime = rcvTime
	s.firstAckElicitingPacketAfterIdleSentTime = time.Time{}
	s.keepAlivePingSent = false

	var log func([]logging.Frame)
	if s.tracer != nil && s.tracer.ReceivedLongHeaderPacket != nil {
		log = func(frames []logging.Frame) {
			s.tracer.ReceivedLongHeaderPacket(packet.hdr, packetSize, ecn, frames)
		}
	}
	isAckEliciting, err := s.handleFrames(packet.data, packet.hdr.DestConnectionID, packet.encryptionLevel, log)
	if err != nil {
		return err
	}
	return s.receivedPacketHandler.ReceivedPacket(packet.hdr.PacketNumber, ecn, packet.encryptionLevel, rcvTime, isAckEliciting)
}

func (s *connection) handleUnpackedShortHeaderPacket(
	destConnID protocol.ConnectionID,
	pn protocol.PacketNumber,
	data []byte,
	ecn protocol.ECN,
	rcvTime time.Time,
	log func([]logging.Frame),
) error {
	s.lastPacketReceivedTime = rcvTime
	s.firstAckElicitingPacketAfterIdleSentTime = time.Time{}
	s.keepAlivePingSent = false

	isAckEliciting, err := s.handleFrames(data, destConnID, protocol.Encryption1RTT, log)
	if err != nil {
		return err
	}
	return s.receivedPacketHandler.ReceivedPacket(pn, ecn, protocol.Encryption1RTT, rcvTime, isAckEliciting)
}

func (s *connection) handleFrames(
	data []byte,
	destConnID protocol.ConnectionID,
	encLevel protocol.EncryptionLevel,
	log func([]logging.Frame),
) (isAckEliciting bool, _ error) {
	// Only used for tracing.
	// If we're not tracing, this slice will always remain empty.
	var frames []logging.Frame
	if log != nil {
		frames = make([]logging.Frame, 0, 4)
	}
	handshakeWasComplete := s.handshakeComplete
	var handleErr error

	for len(data) > 0 {
		l, frame, err := s.frameParser.ParseNext(data, encLevel, s.version)
		if err != nil {
			return false, err
		}
		data = data[l:]
		if frame == nil {
			break
		}
		if ackhandler.IsFrameAckEliciting(frame) {
			isAckEliciting = true
		}
		if log != nil {
			frames = append(frames, logutils.ConvertFrame(frame))
		}
		// An error occurred handling a previous frame.
		// Don't handle the current frame.
		if handleErr != nil {
			continue
		}
		if err := s.handleFrame(frame, encLevel, destConnID); err != nil {
			if log == nil {
				return false, err
			}
			// If we're logging, we need to keep parsing (but not handling) all frames.
			handleErr = err
		}
	}

	if log != nil {
		log(frames)
		if handleErr != nil {
			return false, handleErr
		}
	}

	// Handle completion of the handshake after processing all the frames.
	// This ensures that we correctly handle the following case on the server side:
	// We receive a Handshake packet that contains the CRYPTO frame that allows us to complete the handshake,
	// and an ACK serialized after that CRYPTO frame. In this case, we still want to process the ACK frame.
	if !handshakeWasComplete && s.handshakeComplete {
		if err := s.handleHandshakeComplete(); err != nil {
			return false, err
		}
	}

	return
}

func (s *connection) handleFrame(f wire.Frame, encLevel protocol.EncryptionLevel, destConnID protocol.ConnectionID) error {
	var err error
	wire.LogFrame(s.logger, f, false)
	switch frame := f.(type) {
	case *wire.CryptoFrame:
		err = s.handleCryptoFrame(frame, encLevel)
	case *wire.StreamFrame:
		err = s.handleStreamFrame(frame)
	case *wire.AckFrame:
		err = s.handleAckFrame(frame, encLevel)
	case *wire.ConnectionCloseFrame:
		s.handleConnectionCloseFrame(frame)
	case *wire.ResetStreamFrame:
		err = s.handleResetStreamFrame(frame)
	case *wire.MaxDataFrame:
		s.handleMaxDataFrame(frame)
	case *wire.MaxStreamDataFrame:
		err = s.handleMaxStreamDataFrame(frame)
	case *wire.MaxStreamsFrame:
		s.handleMaxStreamsFrame(frame)
	case *wire.DataBlockedFrame:
	case *wire.StreamDataBlockedFrame:
	case *wire.StreamsBlockedFrame:
	case *wire.StopSendingFrame:
		err = s.handleStopSendingFrame(frame)
	case *wire.PingFrame:
	case *wire.PathChallengeFrame:
		s.handlePathChallengeFrame(frame)
	case *wire.PathResponseFrame:
		// since we don't send PATH_CHALLENGEs, we don't expect PATH_RESPONSEs
		err = errors.New("unexpected PATH_RESPONSE frame")
	case *wire.NewTokenFrame:
		err = s.handleNewTokenFrame(frame)
	case *wire.NewConnectionIDFrame:
		err = s.handleNewConnectionIDFrame(frame)
	case *wire.RetireConnectionIDFrame:
		err = s.handleRetireConnectionIDFrame(frame, destConnID)
	case *wire.HandshakeDoneFrame:
		err = s.handleHandshakeDoneFrame()
	case *wire.DatagramFrame:
		err = s.handleDatagramFrame(frame)
	default:
		err = fmt.Errorf("unexpected frame type: %s", reflect.ValueOf(&frame).Elem().Type().Name())
	}
	return err
}

// handlePacket is called by the server with a new packet
func (s *connection) handlePacket(p receivedPacket) {
	// Discard packets once the amount of queued packets is larger than
	// the channel size, protocol.MaxConnUnprocessedPackets
	select {
	case s.receivedPackets <- p:
	default:
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			//fmt.Println("ONE DOS")
			s.tracer.DroppedPacket(logging.PacketTypeNotDetermined, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropDOSPrevention)
		}
	}
}

func (s *connection) handleConnectionCloseFrame(frame *wire.ConnectionCloseFrame) {
	if frame.IsApplicationError {
		s.closeRemote(&qerr.ApplicationError{
			Remote:       true,
			ErrorCode:    qerr.ApplicationErrorCode(frame.ErrorCode),
			ErrorMessage: frame.ReasonPhrase,
		})
		return
	}
	s.closeRemote(&qerr.TransportError{
		Remote:       true,
		ErrorCode:    qerr.TransportErrorCode(frame.ErrorCode),
		FrameType:    frame.FrameType,
		ErrorMessage: frame.ReasonPhrase,
	})
}

func (s *connection) handleCryptoFrame(frame *wire.CryptoFrame, encLevel protocol.EncryptionLevel) error {
	if err := s.cryptoStreamManager.HandleCryptoFrame(frame, encLevel); err != nil {
		return err
	}
	return s.handleHandshakeEvents()
}

func (s *connection) handleHandshakeEvents() error {
	for {
		ev := s.cryptoStreamHandler.NextEvent()
		var err error
		switch ev.Kind {
		case handshake.EventNoEvent:
			return nil
		case handshake.EventHandshakeComplete:
			// Don't call handleHandshakeComplete yet.
			// It's advantageous to process ACK frames that might be serialized after the CRYPTO frame first.
			s.handshakeComplete = true
		case handshake.EventReceivedTransportParameters:
			err = s.handleTransportParameters(ev.TransportParameters)
		case handshake.EventRestoredTransportParameters:
			s.restoreTransportParameters(ev.TransportParameters)
			close(s.earlyConnReadyChan)
		case handshake.EventReceivedReadKeys:
			// Queue all packets for decryption that have been undecryptable so far.
			s.undecryptablePacketsToProcess = s.undecryptablePackets
			s.undecryptablePackets = nil
		case handshake.EventDiscard0RTTKeys:
			err = s.dropEncryptionLevel(protocol.Encryption0RTT)
		case handshake.EventWriteInitialData:
			_, err = s.initialStream.Write(ev.Data)
		case handshake.EventWriteHandshakeData:
			_, err = s.handshakeStream.Write(ev.Data)
		}
		if err != nil {
			return err
		}
	}
}

func (s *connection) handleStreamFrame(frame *wire.StreamFrame) error {
	str, err := s.streamsMap.GetOrOpenReceiveStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// Stream is closed and already garbage collected
		// ignore this StreamFrame
		return nil
	}
	return str.handleStreamFrame(frame)
}

func (s *connection) handleMaxDataFrame(frame *wire.MaxDataFrame) {
	s.connFlowController.UpdateSendWindow(frame.MaximumData)
}

func (s *connection) handleMaxStreamDataFrame(frame *wire.MaxStreamDataFrame) error {
	str, err := s.streamsMap.GetOrOpenSendStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// stream is closed and already garbage collected
		return nil
	}
	str.updateSendWindow(frame.MaximumStreamData)
	return nil
}

func (s *connection) handleMaxStreamsFrame(frame *wire.MaxStreamsFrame) {
	s.streamsMap.HandleMaxStreamsFrame(frame)
}

func (s *connection) handleResetStreamFrame(frame *wire.ResetStreamFrame) error {
	str, err := s.streamsMap.GetOrOpenReceiveStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// stream is closed and already garbage collected
		return nil
	}
	return str.handleResetStreamFrame(frame)
}

func (s *connection) handleStopSendingFrame(frame *wire.StopSendingFrame) error {
	str, err := s.streamsMap.GetOrOpenSendStream(frame.StreamID)
	if err != nil {
		return err
	}
	if str == nil {
		// stream is closed and already garbage collected
		return nil
	}
	str.handleStopSendingFrame(frame)
	return nil
}

func (s *connection) handlePathChallengeFrame(frame *wire.PathChallengeFrame) {
	s.queueControlFrame(&wire.PathResponseFrame{Data: frame.Data})
}

func (s *connection) handleNewTokenFrame(frame *wire.NewTokenFrame) error {
	if s.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received NEW_TOKEN frame from the client",
		}
	}
	if s.config.TokenStore != nil {
		s.config.TokenStore.Put(s.tokenStoreKey, &ClientToken{data: frame.Token})
	}
	return nil
}

func (s *connection) handleNewConnectionIDFrame(f *wire.NewConnectionIDFrame) error {

	// PACKET_NUMBER_TAG
	if packet_setting.ConnectionInitiationBPFHandler != nil && s.LocalAddr().String() == packet_setting.RELAY_ADDR {
		// Call the handler that makes sure that the initiation of the connection
		// is handled correctly with all the bpf maps
		packet_setting.ConnectionInitiationBPFHandler(f.ConnectionID.Bytes(), uint8(f.ConnectionID.Len()), s)
	}

	return s.connIDManager.Add(f)
}

func (s *connection) handleRetireConnectionIDFrame(f *wire.RetireConnectionIDFrame, destConnID protocol.ConnectionID) error {

	// PACKET_NUMBER_TAG
	if packet_setting.ConnectionRetirementBPFHandler != nil && s.LocalAddr().String() == packet_setting.RELAY_ADDR {
		// Call the handler that makes sure that the retirement of the connection
		// is handled correctly with all the bpf maps
		packet_setting.ConnectionRetirementBPFHandler(destConnID.Bytes(), uint8(destConnID.Len()), s)
	}

	return s.connIDGenerator.Retire(f.SequenceNumber, destConnID)
}

func (s *connection) handleHandshakeDoneFrame() error {
	if s.perspective == protocol.PerspectiveServer {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "received a HANDSHAKE_DONE frame",
		}
	}
	if !s.handshakeConfirmed {
		return s.handleHandshakeConfirmed()
	}
	return nil
}

func (s *connection) handleAckFrame(frame *wire.AckFrame, encLevel protocol.EncryptionLevel) error {

	acked1RTTPacket, err := s.sentPacketHandler.ReceivedAck(frame, encLevel, s.lastPacketReceivedTime)
	if err != nil {
		return err
	}
	if !acked1RTTPacket {
		return nil
	}
	// On the client side: If the packet acknowledged a 1-RTT packet, this confirms the handshake.
	// This is only possible if the ACK was sent in a 1-RTT packet.
	// This is an optimization over simply waiting for a HANDSHAKE_DONE frame, see section 4.1.2 of RFC 9001.
	if s.perspective == protocol.PerspectiveClient && !s.handshakeConfirmed {
		if err := s.handleHandshakeConfirmed(); err != nil {
			return err
		}
	}
	return s.cryptoStreamHandler.SetLargest1RTTAcked(frame.LargestAcked())
}

func (s *connection) handleDatagramFrame(f *wire.DatagramFrame) error {
	if f.Length(s.version) > wire.MaxDatagramSize {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "DATAGRAM frame too large",
		}
	}
	s.datagramQueue.HandleDatagramFrame(f)
	return nil
}

// closeLocal closes the connection and send a CONNECTION_CLOSE containing the error
func (s *connection) closeLocal(e error) {
	s.closeOnce.Do(func() {
		if e == nil {
			s.logger.Infof("Closing connection.")
		} else {
			s.logger.Errorf("Closing connection with error: %s", e)
		}
		s.closeChan <- closeError{err: e, immediate: false, remote: false}
	})
}

// destroy closes the connection without sending the error on the wire
func (s *connection) destroy(e error) {
	s.destroyImpl(e)
	<-s.ctx.Done()
}

func (s *connection) destroyImpl(e error) {
	s.closeOnce.Do(func() {
		if nerr, ok := e.(net.Error); ok && nerr.Timeout() {
			s.logger.Errorf("Destroying connection: %s", e)
		} else {
			s.logger.Errorf("Destroying connection with error: %s", e)
		}
		s.closeChan <- closeError{err: e, immediate: true, remote: false}
	})
}

func (s *connection) closeRemote(e error) {
	s.closeOnce.Do(func() {
		s.logger.Errorf("Peer closed connection with error: %s", e)
		s.closeChan <- closeError{err: e, immediate: true, remote: true}
	})
}

func (s *connection) CloseWithError(code ApplicationErrorCode, desc string) error {
	s.closeLocal(&qerr.ApplicationError{
		ErrorCode:    code,
		ErrorMessage: desc,
	})
	<-s.ctx.Done()
	return nil
}

func (s *connection) closeWithTransportError(code TransportErrorCode) {
	s.closeLocal(&qerr.TransportError{ErrorCode: code})
	<-s.ctx.Done()
}

func (s *connection) handleCloseError(closeErr *closeError) {
	e := closeErr.err
	if e == nil {
		e = &qerr.ApplicationError{}
	} else {
		defer func() {
			closeErr.err = e
		}()
	}

	var (
		statelessResetErr     *StatelessResetError
		versionNegotiationErr *VersionNegotiationError
		recreateErr           *errCloseForRecreating
		applicationErr        *ApplicationError
		transportErr          *TransportError
	)
	switch {
	case errors.Is(e, qerr.ErrIdleTimeout),
		errors.Is(e, qerr.ErrHandshakeTimeout),
		errors.As(e, &statelessResetErr),
		errors.As(e, &versionNegotiationErr),
		errors.As(e, &recreateErr),
		errors.As(e, &applicationErr),
		errors.As(e, &transportErr):
	default:
		e = &qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: e.Error(),
		}
	}

	s.streamsMap.CloseWithError(e)
	s.connIDManager.Close()
	if s.datagramQueue != nil {
		s.datagramQueue.CloseWithError(e)
	}

	if s.tracer != nil && s.tracer.ClosedConnection != nil && !errors.As(e, &recreateErr) {
		s.tracer.ClosedConnection(e)
	}

	// If this is a remote close we're done here
	if closeErr.remote {
		s.connIDGenerator.ReplaceWithClosed(nil)
		return
	}
	if closeErr.immediate {
		s.connIDGenerator.RemoveAll()
		return
	}
	// Don't send out any CONNECTION_CLOSE if this is an error that occurred
	// before we even sent out the first packet.
	if s.perspective == protocol.PerspectiveClient && !s.sentFirstPacket {
		s.connIDGenerator.RemoveAll()
		return
	}
	connClosePacket, err := s.sendConnectionClose(e)
	if err != nil {
		s.logger.Debugf("Error sending CONNECTION_CLOSE: %s", err)
	}
	s.connIDGenerator.ReplaceWithClosed(connClosePacket)
}

func (s *connection) dropEncryptionLevel(encLevel protocol.EncryptionLevel) error {
	if s.tracer != nil && s.tracer.DroppedEncryptionLevel != nil {
		s.tracer.DroppedEncryptionLevel(encLevel)
	}
	s.sentPacketHandler.DropPackets(encLevel)
	s.receivedPacketHandler.DropPackets(encLevel)
	//nolint:exhaustive // only Initial and 0-RTT need special treatment
	switch encLevel {
	case protocol.EncryptionInitial:
		s.droppedInitialKeys = true
		s.cryptoStreamHandler.DiscardInitialKeys()
	case protocol.Encryption0RTT:
		s.streamsMap.ResetFor0RTT()
		if err := s.connFlowController.Reset(); err != nil {
			return err
		}
		return s.framer.Handle0RTTRejection()
	}
	return s.cryptoStreamManager.Drop(encLevel)
}

// is called for the client, when restoring transport parameters saved for 0-RTT
func (s *connection) restoreTransportParameters(params *wire.TransportParameters) {
	if s.logger.Debug() {
		s.logger.Debugf("Restoring Transport Parameters: %s", params)
	}

	s.peerParams = params
	s.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	s.connFlowController.UpdateSendWindow(params.InitialMaxData)
	s.streamsMap.UpdateLimits(params)
	s.connStateMutex.Lock()
	s.connState.SupportsDatagrams = s.supportsDatagrams()
	s.connStateMutex.Unlock()
}

func (s *connection) handleTransportParameters(params *wire.TransportParameters) error {
	if s.tracer != nil && s.tracer.ReceivedTransportParameters != nil {
		s.tracer.ReceivedTransportParameters(params)
	}
	if err := s.checkTransportParameters(params); err != nil {
		return &qerr.TransportError{
			ErrorCode:    qerr.TransportParameterError,
			ErrorMessage: err.Error(),
		}
	}

	if s.perspective == protocol.PerspectiveClient && s.peerParams != nil && s.ConnectionState().Used0RTT && !params.ValidForUpdate(s.peerParams) {
		return &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "server sent reduced limits after accepting 0-RTT data",
		}
	}

	s.peerParams = params
	// On the client side we have to wait for handshake completion.
	// During a 0-RTT connection, we are only allowed to use the new transport parameters for 1-RTT packets.
	if s.perspective == protocol.PerspectiveServer {
		s.applyTransportParameters()
		// On the server side, the early connection is ready as soon as we processed
		// the client's transport parameters.
		close(s.earlyConnReadyChan)
	}

	s.connStateMutex.Lock()
	s.connState.SupportsDatagrams = s.supportsDatagrams()
	s.connStateMutex.Unlock()
	return nil
}

func (s *connection) checkTransportParameters(params *wire.TransportParameters) error {
	if s.logger.Debug() {
		s.logger.Debugf("Processed Transport Parameters: %s", params)
	}

	// check the initial_source_connection_id
	if params.InitialSourceConnectionID != s.handshakeDestConnID {
		return fmt.Errorf("expected initial_source_connection_id to equal %s, is %s", s.handshakeDestConnID, params.InitialSourceConnectionID)
	}

	if s.perspective == protocol.PerspectiveServer {
		return nil
	}
	// check the original_destination_connection_id
	if params.OriginalDestinationConnectionID != s.origDestConnID {
		return fmt.Errorf("expected original_destination_connection_id to equal %s, is %s", s.origDestConnID, params.OriginalDestinationConnectionID)
	}
	if s.retrySrcConnID != nil { // a Retry was performed
		if params.RetrySourceConnectionID == nil {
			return errors.New("missing retry_source_connection_id")
		}
		if *params.RetrySourceConnectionID != *s.retrySrcConnID {
			return fmt.Errorf("expected retry_source_connection_id to equal %s, is %s", s.retrySrcConnID, *params.RetrySourceConnectionID)
		}
	} else if params.RetrySourceConnectionID != nil {
		return errors.New("received retry_source_connection_id, although no Retry was performed")
	}
	return nil
}

func (s *connection) applyTransportParameters() {
	params := s.peerParams
	// Our local idle timeout will always be > 0.
	s.idleTimeout = utils.MinNonZeroDuration(s.config.MaxIdleTimeout, params.MaxIdleTimeout)
	s.keepAliveInterval = min(s.config.KeepAlivePeriod, min(s.idleTimeout/2, protocol.MaxKeepAliveInterval))
	s.streamsMap.UpdateLimits(params)
	s.frameParser.SetAckDelayExponent(params.AckDelayExponent)
	s.connFlowController.UpdateSendWindow(params.InitialMaxData)
	s.rttStats.SetMaxAckDelay(params.MaxAckDelay)
	s.connIDGenerator.SetMaxActiveConnIDs(params.ActiveConnectionIDLimit)
	if params.StatelessResetToken != nil {
		s.connIDManager.SetStatelessResetToken(*params.StatelessResetToken)
	}
	// We don't support connection migration yet, so we don't have any use for the preferred_address.
	if params.PreferredAddress != nil {
		// Retire the connection ID.
		s.connIDManager.AddFromPreferredAddress(params.PreferredAddress.ConnectionID, params.PreferredAddress.StatelessResetToken)
	}
}

func (s *connection) triggerSending(now time.Time) error {
	s.pacingDeadline = time.Time{}

	sendMode := s.sentPacketHandler.SendMode(now)
	//nolint:exhaustive // No need to handle pacing limited here.
	switch sendMode {
	case ackhandler.SendAny:
		return s.sendPackets(now)
	case ackhandler.SendNone:
		return nil
	case ackhandler.SendPacingLimited:
		deadline := s.sentPacketHandler.TimeUntilSend()
		if deadline.IsZero() {
			deadline = deadlineSendImmediately
		}
		s.pacingDeadline = deadline
		// Allow sending of an ACK if we're pacing limit.
		// This makes sure that a peer that is mostly receiving data (and thus has an inaccurate cwnd estimate)
		// sends enough ACKs to allow its peer to utilize the bandwidth.
		fallthrough
	case ackhandler.SendAck:
		// We can at most send a single ACK only packet.
		// There will only be a new ACK after receiving new packets.
		// SendAck is only returned when we're congestion limited, so we don't need to set the pacinggs timer.
		return s.maybeSendAckOnlyPacket(now)
	case ackhandler.SendPTOInitial:
		if err := s.sendProbePacket(protocol.EncryptionInitial, now); err != nil {
			return err
		}
		if s.sendQueue.WouldBlock() {
			s.scheduleSending()
			return nil
		}
		return s.triggerSending(now)
	case ackhandler.SendPTOHandshake:
		if err := s.sendProbePacket(protocol.EncryptionHandshake, now); err != nil {
			return err
		}
		if s.sendQueue.WouldBlock() {
			s.scheduleSending()
			return nil
		}
		return s.triggerSending(now)
	case ackhandler.SendPTOAppData:
		if err := s.sendProbePacket(protocol.Encryption1RTT, now); err != nil {
			return err
		}
		if s.sendQueue.WouldBlock() {
			s.scheduleSending()
			return nil
		}
		return s.triggerSending(now)
	default:
		return fmt.Errorf(" invalid send mode %d", sendMode)
	}
}

func (s *connection) sendPackets(now time.Time) error {
	// Path MTU Discovery
	// Can't use GSO, since we need to send a single packet that's larger than our current maximum size.
	// Performance-wise, this doesn't matter, since we only send a very small (<10) number of
	// MTU probe packets per connection.
	if s.handshakeConfirmed && s.mtuDiscoverer != nil && s.mtuDiscoverer.ShouldSendProbe(now) {
		ping, size := s.mtuDiscoverer.GetPing()
		p, buf, err := s.packer.PackMTUProbePacket(ping, size, s.version)
		if err != nil {
			return err
		}
		ecn := s.sentPacketHandler.ECNMode(true)
		s.logShortHeaderPacket(p.DestConnID, p.Ack, p.Frames, p.StreamFrames, p.PacketNumber, p.PacketNumberLen, p.KeyPhase, ecn, buf.Len(), false)
		s.registerPackedShortHeaderPacket(p, ecn, now)
		s.sendQueue.Send(buf, 0, ecn)
		// This is kind of a hack. We need to trigger sending again somehow.
		s.pacingDeadline = deadlineSendImmediately
		return nil
	}

	if isBlocked, offset := s.connFlowController.IsNewlyBlocked(); isBlocked {
		s.framer.QueueControlFrame(&wire.DataBlockedFrame{MaximumData: offset})
	}
	s.windowUpdateQueue.QueueAll()
	if cf := s.cryptoStreamManager.GetPostHandshakeData(protocol.MaxPostHandshakeCryptoFrameSize); cf != nil {
		s.queueControlFrame(cf)
	}

	if !s.handshakeConfirmed {
		packet, err := s.packer.PackCoalescedPacket(false, s.mtuDiscoverer.CurrentSize(), s.version)
		if err != nil || packet == nil {
			return err
		}
		s.sentFirstPacket = true
		if err := s.sendPackedCoalescedPacket(packet, s.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now); err != nil {
			return err
		}
		sendMode := s.sentPacketHandler.SendMode(now)
		if sendMode == ackhandler.SendPacingLimited {
			s.resetPacingDeadline()
		} else if sendMode == ackhandler.SendAny {
			s.pacingDeadline = deadlineSendImmediately
		}
		return nil
	}

	if s.conn.capabilities().GSO {
		return s.sendPacketsWithGSO(now)
	}
	return s.sendPacketsWithoutGSO(now)
}

func (s *connection) sendPacketsWithoutGSO(now time.Time) error {
	for {
		buf := getPacketBuffer()
		ecn := s.sentPacketHandler.ECNMode(true)
		if _, err := s.appendOneShortHeaderPacket(buf, s.mtuDiscoverer.CurrentSize(), ecn, now); err != nil {
			if err == errNothingToPack {
				buf.Release()
				return nil
			}
			return err
		}

		s.sendQueue.Send(buf, 0, ecn)

		if s.sendQueue.WouldBlock() {
			return nil
		}
		sendMode := s.sentPacketHandler.SendMode(now)
		if sendMode == ackhandler.SendPacingLimited {
			s.resetPacingDeadline()
			return nil
		}
		if sendMode != ackhandler.SendAny {
			return nil
		}
		// Prioritize receiving of packets over sending out more packets.
		if len(s.receivedPackets) > 0 {
			s.pacingDeadline = deadlineSendImmediately
			return nil
		}
	}
}

func (s *connection) sendPacketsWithGSO(now time.Time) error {
	buf := getLargePacketBuffer()
	maxSize := s.mtuDiscoverer.CurrentSize()

	ecn := s.sentPacketHandler.ECNMode(true)
	for {
		var dontSendMore bool
		size, err := s.appendOneShortHeaderPacket(buf, maxSize, ecn, now)
		if err != nil {
			if err != errNothingToPack {
				return err
			}
			if buf.Len() == 0 {
				buf.Release()
				return nil
			}
			dontSendMore = true
		}

		if !dontSendMore {
			sendMode := s.sentPacketHandler.SendMode(now)
			if sendMode == ackhandler.SendPacingLimited {
				s.resetPacingDeadline()
			}
			if sendMode != ackhandler.SendAny {
				dontSendMore = true
			}
		}

		// Don't send more packets in this batch if they require a different ECN marking than the previous ones.
		nextECN := s.sentPacketHandler.ECNMode(true)

		// Append another packet if
		// 1. The congestion controller and pacer allow sending more
		// 2. The last packet appended was a full-size packet
		// 3. The next packet will have the same ECN marking
		// 4. We still have enough space for another full-size packet in the buffer
		if !dontSendMore && size == maxSize && nextECN == ecn && buf.Len()+maxSize <= buf.Cap() {
			continue
		}

		s.sendQueue.Send(buf, uint16(maxSize), ecn)

		if dontSendMore {
			return nil
		}
		if s.sendQueue.WouldBlock() {
			return nil
		}

		// Prioritize receiving of packets over sending out more packets.
		if len(s.receivedPackets) > 0 {
			s.pacingDeadline = deadlineSendImmediately
			return nil
		}

		buf = getLargePacketBuffer()
	}
}

func (s *connection) resetPacingDeadline() {
	deadline := s.sentPacketHandler.TimeUntilSend()
	if deadline.IsZero() {
		deadline = deadlineSendImmediately
	}
	s.pacingDeadline = deadline
}

func (s *connection) maybeSendAckOnlyPacket(now time.Time) error {
	if !s.handshakeConfirmed {
		ecn := s.sentPacketHandler.ECNMode(false)
		packet, err := s.packer.PackCoalescedPacket(true, s.mtuDiscoverer.CurrentSize(), s.version)
		if err != nil {
			return err
		}
		if packet == nil {
			return nil
		}
		return s.sendPackedCoalescedPacket(packet, ecn, now)
	}

	ecn := s.sentPacketHandler.ECNMode(true)
	p, buf, err := s.packer.PackAckOnlyPacket(s.mtuDiscoverer.CurrentSize(), s.version)
	if err != nil {
		if err == errNothingToPack {
			return nil
		}
		return err
	}
	s.logShortHeaderPacket(p.DestConnID, p.Ack, p.Frames, p.StreamFrames, p.PacketNumber, p.PacketNumberLen, p.KeyPhase, ecn, buf.Len(), false)
	s.registerPackedShortHeaderPacket(p, ecn, now)
	s.sendQueue.Send(buf, 0, ecn)
	return nil
}

func (s *connection) sendProbePacket(encLevel protocol.EncryptionLevel, now time.Time) error {
	// Queue probe packets until we actually send out a packet,
	// or until there are no more packets to queue.
	var packet *coalescedPacket
	for {
		if wasQueued := s.sentPacketHandler.QueueProbePacket(encLevel); !wasQueued {
			break
		}
		var err error
		packet, err = s.packer.MaybePackProbePacket(encLevel, s.mtuDiscoverer.CurrentSize(), s.version)
		if err != nil {
			return err
		}
		if packet != nil {
			break
		}
	}
	if packet == nil {
		s.retransmissionQueue.AddPing(encLevel)
		var err error
		packet, err = s.packer.MaybePackProbePacket(encLevel, s.mtuDiscoverer.CurrentSize(), s.version)
		if err != nil {
			return err
		}
	}
	if packet == nil || (len(packet.longHdrPackets) == 0 && packet.shortHdrPacket == nil) {
		return fmt.Errorf("connection BUG: couldn't pack %s probe packet", encLevel)
	}
	return s.sendPackedCoalescedPacket(packet, s.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket()), now)
}

// appendOneShortHeaderPacket appends a new packet to the given packetBuffer.
// If there was nothing to pack, the returned size is 0.
func (s *connection) appendOneShortHeaderPacket(buf *packetBuffer, maxSize protocol.ByteCount, ecn protocol.ECN, now time.Time) (protocol.ByteCount, error) {
	startLen := buf.Len()
	p, err := s.packer.AppendPacket(buf, maxSize, s.version)
	if err != nil {
		return 0, err
	}
	size := buf.Len() - startLen
	s.logShortHeaderPacket(p.DestConnID, p.Ack, p.Frames, p.StreamFrames, p.PacketNumber, p.PacketNumberLen, p.KeyPhase, ecn, size, false)
	s.registerPackedShortHeaderPacket(p, ecn, now)
	return size, nil
}

func (s *connection) registerPackedShortHeaderPacket(p shortHeaderPacket, ecn protocol.ECN, now time.Time) {
	if s.firstAckElicitingPacketAfterIdleSentTime.IsZero() && (len(p.StreamFrames) > 0 || ackhandler.HasAckElicitingFrames(p.Frames)) {
		s.firstAckElicitingPacketAfterIdleSentTime = now
	}

	largestAcked := protocol.InvalidPacketNumber
	if p.Ack != nil {
		largestAcked = p.Ack.LargestAcked()
	}
	// DEBUG_TAG
	// Everything needed for retransmit happens in SentPacket!
	s.sentPacketHandler.SentPacket(now, p.PacketNumber, largestAcked, p.StreamFrames, p.Frames, protocol.Encryption1RTT, ecn, p.Length, p.IsPathMTUProbePacket)
	s.connIDManager.SentPacket()
}

func (s *connection) sendPackedCoalescedPacket(packet *coalescedPacket, ecn protocol.ECN, now time.Time) error {
	s.logCoalescedPacket(packet, ecn)
	for _, p := range packet.longHdrPackets {
		if s.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			s.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.ack != nil {
			largestAcked = p.ack.LargestAcked()
		}
		s.sentPacketHandler.SentPacket(now, p.header.PacketNumber, largestAcked, p.streamFrames, p.frames, p.EncryptionLevel(), ecn, p.length, false)
		if s.perspective == protocol.PerspectiveClient && p.EncryptionLevel() == protocol.EncryptionHandshake &&
			!s.droppedInitialKeys {
			// On the client side, Initial keys are dropped as soon as the first Handshake packet is sent.
			// See Section 4.9.1 of RFC 9001.
			if err := s.dropEncryptionLevel(protocol.EncryptionInitial); err != nil {
				return err
			}
		}
	}
	if p := packet.shortHdrPacket; p != nil {
		if s.firstAckElicitingPacketAfterIdleSentTime.IsZero() && p.IsAckEliciting() {
			s.firstAckElicitingPacketAfterIdleSentTime = now
		}
		largestAcked := protocol.InvalidPacketNumber
		if p.Ack != nil {
			largestAcked = p.Ack.LargestAcked()
		}
		s.sentPacketHandler.SentPacket(now, p.PacketNumber, largestAcked, p.StreamFrames, p.Frames, protocol.Encryption1RTT, ecn, p.Length, p.IsPathMTUProbePacket)
	}
	s.connIDManager.SentPacket()
	s.sendQueue.Send(packet.buffer, 0, ecn)
	return nil
}

func (s *connection) sendConnectionClose(e error) ([]byte, error) {
	var packet *coalescedPacket
	var err error
	var transportErr *qerr.TransportError
	var applicationErr *qerr.ApplicationError
	if errors.As(e, &transportErr) {
		packet, err = s.packer.PackConnectionClose(transportErr, s.mtuDiscoverer.CurrentSize(), s.version)
	} else if errors.As(e, &applicationErr) {
		packet, err = s.packer.PackApplicationClose(applicationErr, s.mtuDiscoverer.CurrentSize(), s.version)
	} else {
		packet, err = s.packer.PackConnectionClose(&qerr.TransportError{
			ErrorCode:    qerr.InternalError,
			ErrorMessage: fmt.Sprintf("connection BUG: unspecified error type (msg: %s)", e.Error()),
		}, s.mtuDiscoverer.CurrentSize(), s.version)
	}
	if err != nil {
		return nil, err
	}
	ecn := s.sentPacketHandler.ECNMode(packet.IsOnlyShortHeaderPacket())
	s.logCoalescedPacket(packet, ecn)
	return packet.buffer.Data, s.conn.Write(packet.buffer.Data, 0, ecn)
}

func (s *connection) logLongHeaderPacket(p *longHeaderPacket, ecn protocol.ECN) {
	// quic-go logging
	if s.logger.Debug() {
		p.header.Log(s.logger)
		if p.ack != nil {
			wire.LogFrame(s.logger, p.ack, true)
		}
		for _, frame := range p.frames {
			wire.LogFrame(s.logger, frame.Frame, true)
		}
		for _, frame := range p.streamFrames {
			wire.LogFrame(s.logger, frame.Frame, true)
		}
	}

	// tracing
	if s.tracer != nil && s.tracer.SentLongHeaderPacket != nil {
		frames := make([]logging.Frame, 0, len(p.frames))
		for _, f := range p.frames {
			frames = append(frames, logutils.ConvertFrame(f.Frame))
		}
		for _, f := range p.streamFrames {
			frames = append(frames, logutils.ConvertFrame(f.Frame))
		}
		var ack *logging.AckFrame
		if p.ack != nil {
			ack = logutils.ConvertAckFrame(p.ack)
		}
		s.tracer.SentLongHeaderPacket(p.header, p.length, ecn, ack, frames)
	}
}

func (s *connection) logShortHeaderPacket(
	destConnID protocol.ConnectionID,
	ackFrame *wire.AckFrame,
	frames []ackhandler.Frame,
	streamFrames []ackhandler.StreamFrame,
	pn protocol.PacketNumber,
	pnLen protocol.PacketNumberLen,
	kp protocol.KeyPhaseBit,
	ecn protocol.ECN,
	size protocol.ByteCount,
	isCoalesced bool,
) {
	if s.logger.Debug() && !isCoalesced {
		s.logger.Debugf("-> Sending packet %d (%d bytes) for connection %s, 1-RTT (ECN: %s)", pn, size, s.logID, ecn)
	}
	// quic-go logging
	if s.logger.Debug() {
		wire.LogShortHeader(s.logger, destConnID, pn, pnLen, kp)
		if ackFrame != nil {
			wire.LogFrame(s.logger, ackFrame, true)
		}
		for _, f := range frames {
			wire.LogFrame(s.logger, f.Frame, true)
		}
		for _, f := range streamFrames {
			wire.LogFrame(s.logger, f.Frame, true)
		}
	}

	// tracing
	if s.tracer != nil && s.tracer.SentShortHeaderPacket != nil {
		fs := make([]logging.Frame, 0, len(frames)+len(streamFrames))
		for _, f := range frames {
			fs = append(fs, logutils.ConvertFrame(f.Frame))
		}
		for _, f := range streamFrames {
			fs = append(fs, logutils.ConvertFrame(f.Frame))
		}
		var ack *logging.AckFrame
		if ackFrame != nil {
			ack = logutils.ConvertAckFrame(ackFrame)
		}
		s.tracer.SentShortHeaderPacket(
			&logging.ShortHeader{
				DestConnectionID: destConnID,
				PacketNumber:     pn,
				PacketNumberLen:  pnLen,
				KeyPhase:         kp,
			},
			size,
			ecn,
			ack,
			fs,
		)
	}
}

func (s *connection) logCoalescedPacket(packet *coalescedPacket, ecn protocol.ECN) {
	if s.logger.Debug() {
		// There's a short period between dropping both Initial and Handshake keys and completion of the handshake,
		// during which we might call PackCoalescedPacket but just pack a short header packet.
		if len(packet.longHdrPackets) == 0 && packet.shortHdrPacket != nil {
			s.logShortHeaderPacket(
				packet.shortHdrPacket.DestConnID,
				packet.shortHdrPacket.Ack,
				packet.shortHdrPacket.Frames,
				packet.shortHdrPacket.StreamFrames,
				packet.shortHdrPacket.PacketNumber,
				packet.shortHdrPacket.PacketNumberLen,
				packet.shortHdrPacket.KeyPhase,
				ecn,
				packet.shortHdrPacket.Length,
				false,
			)
			return
		}
		if len(packet.longHdrPackets) > 1 {
			s.logger.Debugf("-> Sending coalesced packet (%d parts, %d bytes) for connection %s", len(packet.longHdrPackets), packet.buffer.Len(), s.logID)
		} else {
			s.logger.Debugf("-> Sending packet %d (%d bytes) for connection %s, %s", packet.longHdrPackets[0].header.PacketNumber, packet.buffer.Len(), s.logID, packet.longHdrPackets[0].EncryptionLevel())
		}
	}
	for _, p := range packet.longHdrPackets {
		s.logLongHeaderPacket(p, ecn)
	}
	if p := packet.shortHdrPacket; p != nil {
		s.logShortHeaderPacket(p.DestConnID, p.Ack, p.Frames, p.StreamFrames, p.PacketNumber, p.PacketNumberLen, p.KeyPhase, ecn, p.Length, true)
	}
}

// PRIO_PACKS_TAG
// The assumption now is that no matter if priority is actually used or not the
// first byte will always be interpreted as meta data

type PriorityReader interface {
	Read([]byte) (int, error)
}

type PriorityWriter interface {
	Write([]byte) (int, error)
}

// TODONOW: old approach. Still needed?
// PRIO_PACKS_TAG
func readPriorityFromStream(str PriorityReader) Priority {
	if !packet_setting.EXCHANGE_PRIOS {
		return priority_setting.NoPriority
	}
	// Assumption is that first byte always sends the priority
	// This happens only internally and is not exposed to the user
	meta := make([]byte, 1)
	_, err := str.Read(meta)
	if err != nil {
		// panic("Failed to read stream priority when accepting stream")
		//fmt.Println("Failed to read stream priority when accepting stream")
		return priority_setting.NoPriority
	}
	prio := priority_setting.Priority(meta[0])
	//fmt.Println("Internally read priority (1 byte)")
	return prio
}

// TODONOW: old approach. Still needed?
func writePriorityToStream(str PriorityWriter, prio priority_setting.Priority) {
	if !packet_setting.EXCHANGE_PRIOS {
		return
	}
	meta := make([]byte, 1)
	meta[0] = byte(prio)
	_, err := str.Write(meta)
	if err != nil {
		panic("Failed to write stream priority when opening stream")
	}
	//fmt.Println("Internally written priority (1 byte)")
}

// AcceptStream returns the next stream openend by the peer
func (s *connection) AcceptStream(ctx context.Context) (Stream, error) {
	str, err := s.streamsMap.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	str.SetPriority(readPriorityFromStream(str))
	return str, nil
}

func (s *connection) AcceptUniStream(ctx context.Context) (ReceiveStream, error) {
	str, err := s.streamsMap.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	str.SetPriority(readPriorityFromStream(str))
	return str, nil
}

// PRIO_PACKS_TAG
// OpenStream including a user defined priority for potential packet prioritization
func (s *connection) OpenStreamWithPriority(priority priority_setting.Priority) (Stream, error) {
	str, err := s.streamsMap.OpenStreamWithPriority(priority)
	if err != nil {
		return nil, err
	}
	writePriorityToStream(str, priority)
	return str, nil
}

// OpenStream opens a stream
func (s *connection) OpenStream() (Stream, error) {
	return s.OpenStreamWithPriority(priority_setting.NoPriority)
}

// PRIO_PACKS_TAG
// OpenStream including a user defined priority for potential packet prioritization
func (s *connection) OpenStreamSyncWithPriority(ctx context.Context, priority priority_setting.Priority) (Stream, error) {
	str, err := s.streamsMap.OpenStreamSyncWithPriority(ctx, priority)
	if err != nil {
		return nil, err
	}
	writePriorityToStream(str, priority)
	return str, nil
}

func (s *connection) OpenStreamSync(ctx context.Context) (Stream, error) {
	return s.OpenStreamSyncWithPriority(ctx, priority_setting.NoPriority)
}

// PRIO_PACKS_TAG
// OpenStream including a user defined priority for potential packet prioritization
func (s *connection) OpenUniStreamWithPriority(priority priority_setting.Priority) (SendStream, error) {
	str, err := s.streamsMap.OpenUniStreamWithPriority(priority)
	if err != nil {
		return nil, err
	}
	writePriorityToStream(str, priority)
	return str, nil
}

func (s *connection) OpenUniStream() (SendStream, error) {
	return s.OpenUniStreamWithPriority(priority_setting.NoPriority)
}

// PRIO_PACKS_TAG
// OpenStream including a user defined priority for potential packet prioritization
func (s *connection) OpenUniStreamSyncWithPriority(ctx context.Context, priority priority_setting.Priority) (SendStream, error) {
	str, err := s.streamsMap.OpenUniStreamSyncWithPriority(ctx, priority)
	if err != nil {
		return nil, err
	}
	writePriorityToStream(str, priority)
	return str, nil
}

func (s *connection) OpenUniStreamSync(ctx context.Context) (SendStream, error) {
	return s.OpenUniStreamSyncWithPriority(ctx, priority_setting.NoPriority)
}

func (s *connection) newFlowController(id protocol.StreamID) flowcontrol.StreamFlowController {
	initialSendWindow := s.peerParams.InitialMaxStreamDataUni
	if id.Type() == protocol.StreamTypeBidi {
		if id.InitiatedBy() == s.perspective {
			initialSendWindow = s.peerParams.InitialMaxStreamDataBidiRemote
		} else {
			initialSendWindow = s.peerParams.InitialMaxStreamDataBidiLocal
		}
	}
	return flowcontrol.NewStreamFlowController(
		id,
		s.connFlowController,
		protocol.ByteCount(s.config.InitialStreamReceiveWindow),
		protocol.ByteCount(s.config.MaxStreamReceiveWindow),
		initialSendWindow,
		s.onHasStreamWindowUpdate,
		s.rttStats,
		s.logger,
	)
}

// scheduleSending signals that we have data for sending
func (s *connection) scheduleSending() {
	select {
	case s.sendingScheduled <- struct{}{}:
	default:
	}
}

// tryQueueingUndecryptablePacket queues a packet for which we're missing the decryption keys.
// The logging.PacketType is only used for logging purposes.
func (s *connection) tryQueueingUndecryptablePacket(p receivedPacket, pt logging.PacketType) {
	if s.handshakeComplete {
		panic("shouldn't queue undecryptable packets after handshake completion")
	}
	if len(s.undecryptablePackets)+1 > protocol.MaxUndecryptablePackets {
		if s.tracer != nil && s.tracer.DroppedPacket != nil {
			//fmt.Println("TWO DOS")
			s.tracer.DroppedPacket(pt, protocol.InvalidPacketNumber, p.Size(), logging.PacketDropDOSPrevention)
		}
		s.logger.Infof("Dropping undecryptable packet (%d bytes). Undecryptable packet queue full.", p.Size())
		return
	}
	s.logger.Infof("Queueing packet (%d bytes) for later decryption", p.Size())
	if s.tracer != nil && s.tracer.BufferedPacket != nil {
		s.tracer.BufferedPacket(pt, p.Size())
	}
	s.undecryptablePackets = append(s.undecryptablePackets, p)
}

func (s *connection) queueControlFrame(f wire.Frame) {
	s.framer.QueueControlFrame(f)
	s.scheduleSending()
}

func (s *connection) onHasStreamWindowUpdate(id protocol.StreamID) {
	s.windowUpdateQueue.AddStream(id)
	s.scheduleSending()
}

func (s *connection) onHasConnectionWindowUpdate() {
	s.windowUpdateQueue.AddConnection()
	s.scheduleSending()
}

func (s *connection) onHasStreamData(id protocol.StreamID) {
	packet_setting.DebugPrintln("connection.go onHasStreamData")
	s.framer.AddActiveStream(id)
	tmp := s.packer.(*packetPacker).framer.(framer)
	if !reflect.DeepEqual(tmp, s.framer) {
		panic("Framer not the same")
	}

	s.scheduleSending()
}

func (s *connection) onStreamCompleted(id protocol.StreamID) {
	if err := s.streamsMap.DeleteStream(id); err != nil {
		s.closeLocal(err)
	}
}

// DATAGRAM_PRIO_TAG
func (s *connection) SendDatagram(p []byte) error {
	return s.SendDatagramWithPriority(p, priority_setting.NoPriority)
}

// DATAGRAM_PRIO_TAG
func (s *connection) SendDatagramWithPriority(p []byte, prio priority_setting.Priority) error {
	if !s.supportsDatagrams() {
		return errors.New("datagram support disabled")
	}

	f := &wire.DatagramFrame{DataLenPresent: true, Priority: prio}
	if protocol.ByteCount(len(p)) > f.MaxDataLen(s.peerParams.MaxDatagramFrameSize, s.version) {
		return &DatagramTooLargeError{
			PeerMaxDatagramFrameSize: int64(s.peerParams.MaxDatagramFrameSize),
		}
	}
	f.Data = make([]byte, len(p))
	copy(f.Data, p)
	return s.datagramQueue.Add(f)
}

func (s *connection) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	if !s.config.EnableDatagrams {
		return nil, errors.New("datagram support disabled")
	}
	return s.datagramQueue.Receive(ctx)
}

func (s *connection) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

func (s *connection) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *connection) GetVersion() protocol.Version {
	return s.version
}

func (s *connection) NextConnection() Connection {
	<-s.HandshakeComplete()
	s.streamsMap.UseResetMaps()
	return s
}

// PRIO_PACKS_TAG
func (s *connection) GetPriority(sid StreamID) Priority {
	return s.streamsMap.GetPriority(sid)
}

// PACKET_NUMBER_TAG
func (s *connection) SetPacketNumber(pn int64) {

	s.mutex.Lock()
	defer s.mutex.Unlock()

	pn_typed := protocol.PacketNumber(pn)

	if !packet_setting.ALLOW_SETTING_PN {
		//fmt.Println("Trying to set packet number when not allowed (connection.go)")
		return
	}
	sph := s.sentPacketHandler
	sph.SetPacketNumber(pn_typed)
}

func (s *connection) SetHighestSent(pn int64) {

	s.mutex.Lock() // TODO: need to lock?
	defer s.mutex.Unlock()

	pn_typed := protocol.PacketNumber(pn)
	s.sentPacketHandler.SetHighestSentPacketNumber(pn_typed)
}

func (s *connection) Lock() {
	s.mutex.Lock()
}

func (s *connection) Unlock() {
	s.mutex.Unlock()
}

// BPF_RETRANSMISSION_TAG
func (s *connection) UpdatePacketNumberMapping(mapping packet_setting.PacketNumberMapping) {
	// //fmt.Println("Updating pn from", mapping.OriginalPacketNumber, "to", mapping.NewPacketNumber)
	s.sentPacketHandler.UpdatePacketNumberMapping(mapping)
}

// BPF_CC_TAG
func (s *connection) RegisterBPFPacket(prc packet_setting.PacketRegisterContainerBPF) {

	// TODO: what needs to be done here:
	// 1. Parse the packet and get the stream frames
	// 2. Create a sendstream for each frame in the stream frames (and potentially reuse them)
	// 3. Change the OnLost function of the send_stream to handle bpf retranmissions separately
	// 4. Make sure the Registering method of sentPacketHandler has access to the handlers to correctly use them
	// 5. Register the packet with the sent packet handler

	// Set the frames for the packet
	_, stream_frames, err := s.parseBPFSavedRawData(prc.RawData)
	if err != nil {
		if strings.Contains(err.Error(), "Datagram") {
			//fmt.Println("Ignoring DatagramFrame for registration")
			return // We ignore datagram packets here since we cannot rule them out earlier (// TODO: we probably could rule them out in the BPF code)
		}
		panic(err)
	}
	if len(stream_frames) == 0 {
		return
	}

	prc.Frames = make([]packet_setting.GeneralFrame, 0)
	prc.StreamFrames = stream_frames

	handler_lut := make(map[protocol.StreamID]ackhandler.FrameHandler)
	for _, sf := range stream_frames {

		id := sf.StreamID
		sender := s.streamsMap.GetSender()
		nfc := s.streamsMap.GetNewFlowController()

		str := newSendStream(id, *sender, (*nfc)(id))

		s.streamsMap.AddToStreams(protocol.StreamID(id), str)

		str.overwrittenOnLost = OnLost
		str.overwrittenOnAcked = OnAcked
		str.lostPacketNumber = prc.PacketNumber

		if packet_setting.MarkStreamIdAsRetransmission != nil { // ! TODONOW: still needded (seems that way)? -> why still needed?
			packet_setting.MarkStreamIdAsRetransmission(uint64(id), s) // TODO: type int64 to uint64 ok?
		}

		handler_lut[sf.StreamID] = (*sendStreamAckHandler)(str)
	}

	s.sentPacketHandler.RegisterBPFPacket(prc, handler_lut)
}

func OnAcked(f wire.Frame) {
	// TODO: prolly remove payload saved in map
}

func OnLost(f wire.Frame, s *sendStreamAckHandler) {

	if !packet_setting.IS_RELAY {
		panic("This code should only be executed on the relay")
	}

	sf := f.(*wire.StreamFrame)

	if s.streamID != sf.StreamID {
		panic("Stream ID mismatch")
	}

	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	sf.DataLenPresent = true
	if len(sf.Data) == 0 {
		fmt.Println("No data in stream frame") // TODO: why happening? - I thought this might happen since the data cannot be found if the retransmit is a retransmit of a retransmit but seems to happen because of smth else
		return
	}

	// TODO:
	// This seems to be a workaround for the problem that the lib does not send retransmissions reliably if i just add them to the retransmission queue
	// The problem here seems to be that the header needs to be set manually as well - this might even be a good thing since the header flags are dependent
	// on the data that is sent anyway, e.g. fin flag and a new stream might screw this up.
	// Things to consider:
	// header form seem trivial since only short header packets should be considered here (todo: long header packets from setup considered normally already?)
	// packet number length is fixed to 4 bytes iirc
	// destination conn id might be tricky? but the connection is known so it should be gettable somehow
	// packetnumber is known from registration - is it also known here? -> doesnt matter since the old pn is not needed / a new one is used. This might screw with the "telling bpf about a retransmit" though
	// payload is obviously known

	conn := s.sender.(*connection)
	conn_id := conn.connIDManager.activeConnectionID
	pn := conn.sentPacketHandler.PopPacketNumber(protocol.Encryption1RTT)
	pnLen := protocol.PacketNumberLen2
	offset := sf.Offset
	lostPn := s.lostPacketNumber

	if packet_setting.RetransmissionPacketNumberTranslationHandler != nil {
		packet_setting.RetransmissionPacketNumberTranslationHandler(lostPn, int64(pn), conn)
	}

	// TODO: tell bpf about retransmit with this pn
	if packet_setting.MarkPacketAsRetransmission != nil {
		packet_identifier := packet_setting.PacketIdentifierStruct{
			PacketNumber:    uint64(pn),
			StreamID:        uint64(sf.StreamID),
			ConnectionID:    conn_id.Bytes(),
			ConnectionIDLen: uint8(conn_id.Len()),
		}
		packet_setting.MarkPacketAsRetransmission(packet_identifier)
	}

	sh_buf := make([]byte, 0)
	sh_buf, err := wire.AppendShortHeader(sh_buf, conn_id, pn, pnLen, protocol.KeyPhaseZero)
	if err != nil {
		panic(err)
	}
	datasize := len(sh_buf) + len(sf.Data) + 1 /* frame type */ + 8 /* stream id */ + 0 /* padding length todo: why 1??? */

	var pack_buf *packetBuffer
	if datasize <= protocol.MaxPacketBufferSize {
		pack_buf = getPacketBuffer()
	} else if datasize <= protocol.MaxLargePacketBufferSize {
		pack_buf = getLargePacketBuffer()
	} else {
		panic("Packet too large")
	}

	pack_buf.Data = append(pack_buf.Data, sh_buf...) // adding short header

	frame_header := make([]byte, 1)
	frame_header[0] = 0x08                                                            // Stream frame type
	frame_header = quicvarint.AppendWithMinSize(frame_header, uint64(sf.StreamID), 8) // fixed size of 8 bytes for stream id
	if offset > 0 {
		frame_header = quicvarint.Append(frame_header, uint64(offset))
		frame_header[0] |= 0x04 // set offset bit
	}

	frame_header_with_data := append(frame_header, sf.Data...)

	// We need to store the data (with the frame header already attached) in the retransmission "cache".
	// This makes the data accessible if the retransmission gets lost.
	if packet_setting.StoreRelayPacket != nil {
		data_dup := make([]byte, len(frame_header_with_data))
		copy(data_dup, frame_header_with_data)

		ts := time.Now().UnixNano()

		packet_setting.StoreRelayPacket(int64(pn), ts, data_dup, nil) // TODO: conn not used rn? only necessary in case of using this library for multiple connections?
	}

	pack_buf.Data = append(pack_buf.Data, frame_header_with_data...) // adding frame header and data

	conn.sendQueue.Send(pack_buf, 0, protocol.ECNNon)

	s.mutex.Unlock()

	// TODO: for some reason this approach does not work even thought the "normal"
	// TODO: OnLost function does it this way.
	// s.retransmissionQueue = append(s.retransmissionQueue, sf)
	// s.mutex.Unlock()
	// s.sender.onHasStreamData(s.streamID)

}

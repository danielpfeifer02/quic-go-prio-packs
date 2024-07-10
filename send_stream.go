package quic

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/ackhandler"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/flowcontrol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/qerr"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/utils"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/wire"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

type sendStreamI interface {
	SendStream
	handleStopSendingFrame(*wire.StopSendingFrame)
	hasData() bool
	popStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (frame ackhandler.StreamFrame, ok, hasMore bool)
	closeForShutdown(error)
	updateSendWindow(protocol.ByteCount)
}

type sendStream struct {
	mutex sync.Mutex

	numOutstandingFrames int64
	retransmissionQueue  []*wire.StreamFrame

	ctx       context.Context
	ctxCancel context.CancelCauseFunc

	streamID protocol.StreamID
	sender   streamSender

	writeOffset protocol.ByteCount

	cancelWriteErr      error
	closeForShutdownErr error

	finishedWriting bool // set once Close() is called
	finSent         bool // set when a STREAM_FRAME with FIN bit has been sent
	completed       bool // set when this stream has been reported to the streamSender as completed

	dataForWriting []byte // during a Write() call, this slice is the part of p that still needs to be sent out
	nextFrame      *wire.StreamFrame

	writeChan chan struct{}
	writeOnce chan struct{}
	deadline  time.Time

	flowController flowcontrol.StreamFlowController

	// PRIO_PACKS_TAG
	priority priority_setting.Priority

	// RETRANSMISSION_TAG
	overwrittenOnLost  func(wire.Frame, *sendStream)
	overwrittenOnAcked func(wire.Frame)
}

var (
	_ SendStream  = &sendStream{}
	_ sendStreamI = &sendStream{}
)

func newSendStream(
	streamID protocol.StreamID,
	sender streamSender,
	flowController flowcontrol.StreamFlowController,
) *sendStream {
	s := &sendStream{
		streamID:       streamID,
		sender:         sender,
		flowController: flowController,
		writeChan:      make(chan struct{}, 1),
		writeOnce:      make(chan struct{}, 1), // cap: 1, to protect against concurrent use of Write
		// PRIO_PACKS_TAG
		priority: priority_setting.NoPriority,

		// RETRANSMISSION_TAG
		overwrittenOnLost:  nil,
		overwrittenOnAcked: nil,
	}
	s.ctx, s.ctxCancel = context.WithCancelCause(context.Background())
	return s
}

func (s *sendStream) StreamID() protocol.StreamID {
	return s.streamID // same for receiveStream and sendStream
}

func (s *sendStream) Write(p []byte) (int, error) {
	return s.WriteFinConsidering(p, false, &wire.StreamFrame{})
}

// RETRANSMISSION_TAG
func (s *sendStream) WriteFinConsidering(p []byte, forceFin bool, sf *wire.StreamFrame) (int, error) {
	// Concurrent use of Write is not permitted (and doesn't make any sense),
	// but sometimes people do it anyway.
	// Make sure that we only execute one call at any given time to avoid hard to debug failures.
	s.writeOnce <- struct{}{}
	defer func() { <-s.writeOnce }()

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.finishedWriting {
		return 0, fmt.Errorf("write on closed stream %d", s.streamID)
	}
	if s.cancelWriteErr != nil {
		return 0, s.cancelWriteErr
	}
	if s.closeForShutdownErr != nil {
		return 0, s.closeForShutdownErr
	}
	if !s.deadline.IsZero() && !time.Now().Before(s.deadline) {
		return 0, errDeadline
	}
	if len(p) == 0 {
		return 0, nil
	}

	s.dataForWriting = p

	var (
		deadlineTimer  *utils.Timer
		bytesWritten   int
		notifiedSender bool
	)
	for {
		var copied bool
		var deadline time.Time
		// As soon as dataForWriting becomes smaller than a certain size x, we copy all the data to a STREAM frame (s.nextFrame),
		// which can then be popped the next time we assemble a packet.
		// This allows us to return Write() when all data but x bytes have been sent out.
		// When the user now calls Close(), this is much more likely to happen before we popped that last STREAM frame,
		// allowing us to set the FIN bit on that frame (instead of sending an empty STREAM frame with FIN).
		if s.canBufferStreamFrame() && len(s.dataForWriting) > 0 {

			// if packet_setting.IS_RELAY {
			// 	fmt.Println("Test-------------------------------------------------")
			// 	fmt.Println(hex.Dump(s.dataForWriting))
			// }

			if s.nextFrame == nil {
				f := wire.GetStreamFrame()

				// RETRANSMISSION_TAG
				// TODO: correct to only have here?
				if forceFin {
					f.Fin = sf.Fin
					f.Offset = sf.Offset
					f.DataLenPresent = sf.DataLenPresent
					// f.Data = sf.Data
				}

				f.Offset = s.writeOffset
				f.StreamID = s.streamID
				f.DataLenPresent = true
				f.Data = f.Data[:len(s.dataForWriting)]
				copy(f.Data, s.dataForWriting)
				s.nextFrame = f

				// RETRANSMISSION_TAG
				if forceFin {
					s.nextFrame = sf
				}
			} else {
				l := len(s.nextFrame.Data)
				s.nextFrame.Data = s.nextFrame.Data[:l+len(s.dataForWriting)]
				copy(s.nextFrame.Data[l:], s.dataForWriting)
			}
			s.dataForWriting = nil
			bytesWritten = len(p)
			copied = true
		} else {
			bytesWritten = len(p) - len(s.dataForWriting)
			deadline = s.deadline
			if !deadline.IsZero() {
				if !time.Now().Before(deadline) {
					s.dataForWriting = nil
					return bytesWritten, errDeadline
				}
				if deadlineTimer == nil {
					deadlineTimer = utils.NewTimer()
					defer deadlineTimer.Stop()
				}
				deadlineTimer.Reset(deadline)
			}
			if s.dataForWriting == nil || s.cancelWriteErr != nil || s.closeForShutdownErr != nil {
				packet_setting.DebugPrintln("break nil") // TODONOW: remove
				break
			}
		}

		s.mutex.Unlock()
		if !notifiedSender {
			s.sender.onHasStreamData(s.streamID) // must be called without holding the mutex
			notifiedSender = true
			// fmt.Println("notifiedSender-----------------------------------------")
		}
		if copied {
			s.mutex.Lock()
			// fmt.Println("break copied") // TODONOW: remove
			break
		}
		if deadline.IsZero() {
			<-s.writeChan
		} else {
			select {
			case <-s.writeChan:
			case <-deadlineTimer.Chan():
				deadlineTimer.SetRead()
			}
		}
		s.mutex.Lock()
		fmt.Println("Not written in one take") // TODONOW: remove
	}

	if bytesWritten == len(p) {
		return bytesWritten, nil
	}
	if s.closeForShutdownErr != nil {
		return bytesWritten, s.closeForShutdownErr
	} else if s.cancelWriteErr != nil {
		return bytesWritten, s.cancelWriteErr
	}
	return bytesWritten, nil
}

func (s *sendStream) canBufferStreamFrame() bool {
	var l protocol.ByteCount
	if s.nextFrame != nil {
		l = s.nextFrame.DataLen()
	}
	return l+protocol.ByteCount(len(s.dataForWriting)) <= protocol.MaxPacketBufferSize
}

// popStreamFrame returns the next STREAM frame that is supposed to be sent on this stream
// maxBytes is the maximum length this frame (including frame header) will have.
func (s *sendStream) popStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (af ackhandler.StreamFrame, ok, hasMore bool) {
	s.mutex.Lock()
	f, hasMoreData := s.popNewOrRetransmittedStreamFrame(maxBytes, v)

	if f != nil {
		s.numOutstandingFrames++
		packet_setting.DebugPrintln(hex.Dump(f.Data))
	}
	s.mutex.Unlock()

	if f == nil {
		return ackhandler.StreamFrame{}, false, hasMoreData
	}
	return ackhandler.StreamFrame{
		Frame:   f,
		Handler: (*sendStreamAckHandler)(s),
	}, true, hasMoreData
}

func (s *sendStream) popNewOrRetransmittedStreamFrame(maxBytes protocol.ByteCount, v protocol.Version) (*wire.StreamFrame, bool /* has more data to send */) {
	if s.cancelWriteErr != nil || s.closeForShutdownErr != nil {
		return nil, false
	}

	if len(s.retransmissionQueue) > 0 {
		// DEBUG_TAG
		f, hasMoreRetransmissions := s.maybeGetRetransmission(maxBytes, v)
		if f != nil || hasMoreRetransmissions {
			if f == nil {
				return nil, true
			}

			if f.Data[0] == 0x69 { // TODONOW: remove
				fmt.Println("popNewOrRetransmittedStreamFrame: retransmissionQueue")
			} else {
				fmt.Println("Userspace retransmissionQueue")
			}
			// We always claim that we have more data to send.
			// This might be incorrect, in which case there'll be a spurious call to popStreamFrame in the future.
			return f, true
		}
	}

	if len(s.dataForWriting) == 0 && s.nextFrame == nil {
		if s.finishedWriting && !s.finSent {
			s.finSent = true
			return &wire.StreamFrame{
				StreamID:       s.streamID,
				Offset:         s.writeOffset,
				DataLenPresent: true,
				Fin:            true,
			}, false
		}
		return nil, false
	}

	sendWindow := s.flowController.SendWindowSize()
	if sendWindow == 0 {
		if isBlocked, offset := s.flowController.IsNewlyBlocked(); isBlocked {
			s.sender.queueControlFrame(&wire.StreamDataBlockedFrame{
				StreamID:          s.streamID,
				MaximumStreamData: offset,
			})
			return nil, false
		}
		return nil, true
	}

	f, hasMoreData := s.popNewStreamFrame(maxBytes, sendWindow, v)
	if dataLen := f.DataLen(); dataLen > 0 {
		s.writeOffset += f.DataLen()
		s.flowController.AddBytesSent(f.DataLen())
	}
	f.Fin = s.finishedWriting && s.dataForWriting == nil && s.nextFrame == nil && !s.finSent
	if f.Fin {
		s.finSent = true
	}

	if f.Data[0] == 0x69 {
		fmt.Println("popNewOrRetransmittedStreamFrame: popNewStreamFrame") // TODONOW: remove
	}
	return f, hasMoreData
}

func (s *sendStream) popNewStreamFrame(maxBytes, sendWindow protocol.ByteCount, v protocol.Version) (*wire.StreamFrame, bool) {
	if s.nextFrame != nil {
		nextFrame := s.nextFrame
		s.nextFrame = nil

		maxDataLen := min(sendWindow, nextFrame.MaxDataLen(maxBytes, v))
		if nextFrame.DataLen() > maxDataLen {
			s.nextFrame = wire.GetStreamFrame()
			s.nextFrame.StreamID = s.streamID
			s.nextFrame.Offset = s.writeOffset + maxDataLen
			s.nextFrame.Data = s.nextFrame.Data[:nextFrame.DataLen()-maxDataLen]
			s.nextFrame.DataLenPresent = true
			copy(s.nextFrame.Data, nextFrame.Data[maxDataLen:])
			nextFrame.Data = nextFrame.Data[:maxDataLen]
		} else {
			s.signalWrite()
		}
		return nextFrame, s.nextFrame != nil || s.dataForWriting != nil
	}

	f := wire.GetStreamFrame()
	f.Fin = false
	f.StreamID = s.streamID
	f.Offset = s.writeOffset
	f.DataLenPresent = true
	f.Data = f.Data[:0]

	hasMoreData := s.popNewStreamFrameWithoutBuffer(f, maxBytes, sendWindow, v)
	if len(f.Data) == 0 && !f.Fin {
		f.PutBack()
		return nil, hasMoreData
	}
	return f, hasMoreData
}

func (s *sendStream) popNewStreamFrameWithoutBuffer(f *wire.StreamFrame, maxBytes, sendWindow protocol.ByteCount, v protocol.Version) bool {
	maxDataLen := f.MaxDataLen(maxBytes, v)
	if maxDataLen == 0 { // a STREAM frame must have at least one byte of data
		return s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
	}
	s.getDataForWriting(f, min(maxDataLen, sendWindow))

	return s.dataForWriting != nil || s.nextFrame != nil || s.finishedWriting
}

func (s *sendStream) maybeGetRetransmission(maxBytes protocol.ByteCount, v protocol.Version) (*wire.StreamFrame, bool /* has more retransmissions */) {
	f := s.retransmissionQueue[0]
	newFrame, needsSplit := f.MaybeSplitOffFrame(maxBytes, v)
	if needsSplit {
		return newFrame, true
	}
	s.retransmissionQueue = s.retransmissionQueue[1:]
	// TODONOW: can it happen here that more than one stream frame will end up in a packet?
	// TODONOW: do we even care about this since its sent from userspace and bpf only changes pn etc?
	return f, len(s.retransmissionQueue) > 0
}

func (s *sendStream) hasData() bool {
	s.mutex.Lock()
	hasData := len(s.dataForWriting) > 0
	s.mutex.Unlock()
	return hasData
}

func (s *sendStream) getDataForWriting(f *wire.StreamFrame, maxBytes protocol.ByteCount) {
	if protocol.ByteCount(len(s.dataForWriting)) <= maxBytes {
		f.Data = f.Data[:len(s.dataForWriting)]
		copy(f.Data, s.dataForWriting)
		s.dataForWriting = nil
		s.signalWrite()
		return
	}
	f.Data = f.Data[:maxBytes]
	copy(f.Data, s.dataForWriting)
	s.dataForWriting = s.dataForWriting[maxBytes:]
	if s.canBufferStreamFrame() {
		s.signalWrite()
	}
}

func (s *sendStream) isNewlyCompleted() bool {
	completed := (s.finSent || s.cancelWriteErr != nil) && s.numOutstandingFrames == 0 && len(s.retransmissionQueue) == 0
	if completed && !s.completed {
		s.completed = true
		return true
	}
	return false
}

func (s *sendStream) Close() error {
	s.mutex.Lock()
	if s.closeForShutdownErr != nil {
		s.mutex.Unlock()
		return nil
	}
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return fmt.Errorf("close called for canceled stream %d", s.streamID)
	}
	s.ctxCancel(nil)
	s.finishedWriting = true
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID) // need to send the FIN, must be called without holding the mutex
	return nil
}

func (s *sendStream) CancelWrite(errorCode StreamErrorCode) {
	s.cancelWriteImpl(errorCode, false)
}

// must be called after locking the mutex
func (s *sendStream) cancelWriteImpl(errorCode qerr.StreamErrorCode, remote bool) {
	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	s.cancelWriteErr = &StreamError{StreamID: s.streamID, ErrorCode: errorCode, Remote: remote}
	s.ctxCancel(s.cancelWriteErr)
	s.numOutstandingFrames = 0
	s.retransmissionQueue = nil
	newlyCompleted := s.isNewlyCompleted()
	s.mutex.Unlock()

	s.signalWrite()
	s.sender.queueControlFrame(&wire.ResetStreamFrame{
		StreamID:  s.streamID,
		FinalSize: s.writeOffset,
		ErrorCode: errorCode,
	})
	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStream) updateSendWindow(limit protocol.ByteCount) {
	updated := s.flowController.UpdateSendWindow(limit)
	if !updated { // duplicate or reordered MAX_STREAM_DATA frame
		return
	}
	s.mutex.Lock()
	hasStreamData := s.dataForWriting != nil || s.nextFrame != nil
	s.mutex.Unlock()
	if hasStreamData {
		s.sender.onHasStreamData(s.streamID)
	}
}

func (s *sendStream) handleStopSendingFrame(frame *wire.StopSendingFrame) {
	s.cancelWriteImpl(frame.ErrorCode, true)
}

func (s *sendStream) Context() context.Context {
	return s.ctx
}

func (s *sendStream) SetWriteDeadline(t time.Time) error {
	s.mutex.Lock()
	s.deadline = t
	s.mutex.Unlock()
	s.signalWrite()
	return nil
}

// CloseForShutdown closes a stream abruptly.
// It makes Write unblock (and return the error) immediately.
// The peer will NOT be informed about this: the stream is closed without sending a FIN or RST.
func (s *sendStream) closeForShutdown(err error) {
	s.mutex.Lock()
	s.ctxCancel(err)
	s.closeForShutdownErr = err
	s.mutex.Unlock()
	s.signalWrite()
}

// signalWrite performs a non-blocking send on the writeChan
func (s *sendStream) signalWrite() {
	select {
	case s.writeChan <- struct{}{}:
		// fmt.Println("signalWrite", hex.Dump(s.nextFrame.Data[:10])) // TODONOW: remove
	default:
	}
}

// PRIO_PACKS_TAG
// Priority returns the priority of the stream
func (s *sendStream) Priority() priority_setting.Priority {
	return s.priority
}

// PRIO_PACKS_TAG
// SetPriority sets the priority of the stream
func (s *sendStream) SetPriority(priority priority_setting.Priority) {
	s.priority = priority
}

type sendStreamAckHandler sendStream

var _ ackhandler.FrameHandler = &sendStreamAckHandler{}

func (s *sendStreamAckHandler) OnAcked(f wire.Frame) {

	if s.overwrittenOnAcked != nil {
		s.overwrittenOnAcked(f)
		return
	}

	sf := f.(*wire.StreamFrame)
	sf.PutBack()
	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	newlyCompleted := (*sendStream)(s).isNewlyCompleted()
	s.mutex.Unlock()

	if newlyCompleted {
		s.sender.onStreamCompleted(s.streamID)
	}
}

func (s *sendStreamAckHandler) OnLost(f wire.Frame) {

	if s.overwrittenOnLost != nil {
		s.overwrittenOnLost(f, (*sendStream)(s))
		return
	}

	sf := f.(*wire.StreamFrame)
	fmt.Println("sendStreamAckHandler: OnLost", sf.StreamID) // TODONOW: why not showing? other OnLost called?

	s.mutex.Lock()
	if s.cancelWriteErr != nil {
		s.mutex.Unlock()
		return
	}
	sf.DataLenPresent = true
	s.retransmissionQueue = append(s.retransmissionQueue, sf)
	s.numOutstandingFrames--
	if s.numOutstandingFrames < 0 {
		panic("numOutStandingFrames negative")
	}
	s.mutex.Unlock()

	s.sender.onHasStreamData(s.streamID)
}

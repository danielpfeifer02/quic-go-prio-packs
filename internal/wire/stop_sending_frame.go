package wire

import (
	"bytes"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/qerr"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/quicvarint"
)

// A StopSendingFrame is a STOP_SENDING frame
type StopSendingFrame struct {
	StreamID  protocol.StreamID
	ErrorCode qerr.StreamErrorCode
}

// parseStopSendingFrame parses a STOP_SENDING frame
func parseStopSendingFrame(r *bytes.Reader, _ protocol.Version) (*StopSendingFrame, error) {
	streamID, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	errorCode, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	return &StopSendingFrame{
		StreamID:  protocol.StreamID(streamID),
		ErrorCode: qerr.StreamErrorCode(errorCode),
	}, nil
}

// Length of a written frame
func (f *StopSendingFrame) Length(_ protocol.Version) protocol.ByteCount {
	// STREAM_ID_LENGTH_TAG
	// TODO: might not be necessary for this frame
	var sid_len protocol.ByteCount
	if packet_setting.BPF_TURNED_ON {
		sid_len = 8
	} else {
		sid_len = quicvarint.Len(uint64(f.StreamID))
	}
	return 1 + sid_len + quicvarint.Len(uint64(f.ErrorCode))
}

func (f *StopSendingFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, stopSendingFrameType)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.ErrorCode))
	return b, nil
}

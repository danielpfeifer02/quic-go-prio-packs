package wire

import (
	"bytes"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/quicvarint"
)

// A StreamDataBlockedFrame is a STREAM_DATA_BLOCKED frame
type StreamDataBlockedFrame struct {
	StreamID          protocol.StreamID
	MaximumStreamData protocol.ByteCount
}

func parseStreamDataBlockedFrame(r *bytes.Reader, _ protocol.Version) (*StreamDataBlockedFrame, error) {
	sid, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}
	offset, err := quicvarint.Read(r)
	if err != nil {
		return nil, err
	}

	return &StreamDataBlockedFrame{
		StreamID:          protocol.StreamID(sid),
		MaximumStreamData: protocol.ByteCount(offset),
	}, nil
}

func (f *StreamDataBlockedFrame) Append(b []byte, _ protocol.Version) ([]byte, error) {
	b = append(b, 0x15)
	b = quicvarint.Append(b, uint64(f.StreamID))
	b = quicvarint.Append(b, uint64(f.MaximumStreamData))
	return b, nil
}

// Length of a written frame
func (f *StreamDataBlockedFrame) Length(version protocol.Version) protocol.ByteCount {
	// STREAM_ID_LENGTH_TAG
	// TODO: might not be necessary for this frame
	var sid_len protocol.ByteCount
	if packet_setting.BPF_TURNED_ON {
		sid_len = 8
	} else {
		sid_len = quicvarint.Len(uint64(f.StreamID))
	}
	return 1 + sid_len + quicvarint.Len(uint64(f.MaximumStreamData))
}

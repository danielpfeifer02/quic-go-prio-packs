package quic

import (
	"bytes"
	"fmt"
	"reflect"
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/handshake"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/qerr"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/wire"
	crypto_settings "golang.org/x/crypto"
)

type headerDecryptor interface {
	DecryptHeader(sample []byte, firstByte *byte, pnBytes []byte)
}

type headerParseError struct {
	err error
}

func (e *headerParseError) Unwrap() error {
	return e.err
}

func (e *headerParseError) Error() string {
	return e.err.Error()
}

type unpackedPacket struct {
	hdr             *wire.ExtendedHeader
	encryptionLevel protocol.EncryptionLevel
	data            []byte
}

// The packetUnpacker unpacks QUIC packets.
type packetUnpacker struct {
	cs handshake.CryptoSetup

	shortHdrConnIDLen int
}

var _ unpacker = &packetUnpacker{}

func newPacketUnpacker(cs handshake.CryptoSetup, shortHdrConnIDLen int) *packetUnpacker {
	return &packetUnpacker{
		cs:                cs,
		shortHdrConnIDLen: shortHdrConnIDLen,
	}
}

// UnpackLongHeader unpacks a Long Header packet.
// If the reserved bits are invalid, the error is wire.ErrInvalidReservedBits.
// If any other error occurred when parsing the header, the error is of type headerParseError.
// If decrypting the payload fails for any reason, the error is the error returned by the AEAD.
func (u *packetUnpacker) UnpackLongHeader(hdr *wire.Header, rcvTime time.Time, data []byte, v protocol.Version) (*unpackedPacket, error) {
	var encLevel protocol.EncryptionLevel
	var extHdr *wire.ExtendedHeader
	var decrypted []byte
	//nolint:exhaustive // Retry packets can't be unpacked.
	switch hdr.Type {
	case protocol.PacketTypeInitial:
		encLevel = protocol.EncryptionInitial
		opener, err := u.cs.GetInitialOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackLongHeaderPacket(opener, hdr, data, v)
		if err != nil {
			return nil, err
		}
	case protocol.PacketTypeHandshake:
		encLevel = protocol.EncryptionHandshake
		opener, err := u.cs.GetHandshakeOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackLongHeaderPacket(opener, hdr, data, v)
		if err != nil {
			return nil, err
		}
	case protocol.PacketType0RTT:
		encLevel = protocol.Encryption0RTT
		opener, err := u.cs.Get0RTTOpener()
		if err != nil {
			return nil, err
		}
		extHdr, decrypted, err = u.unpackLongHeaderPacket(opener, hdr, data, v)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown packet type: %s", hdr.Type)
	}

	if len(decrypted) == 0 {
		return nil, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "empty packet",
		}
	}

	return &unpackedPacket{
		hdr:             extHdr,
		encryptionLevel: encLevel,
		data:            decrypted,
	}, nil
}

func (u *packetUnpacker) UnpackShortHeader(rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
	opener, err := u.cs.Get1RTTOpener()

	if err != nil {
		return 0, 0, 0, nil, err
	}
	pn, pnLen, kp, decrypted, err := u.unpackShortHeaderPacket(opener, rcvTime, data)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	if len(decrypted) == 0 {
		return 0, 0, 0, nil, &qerr.TransportError{
			ErrorCode:    qerr.ProtocolViolation,
			ErrorMessage: "empty packet",
		}
	}
	return pn, pnLen, kp, decrypted, nil
}

func (u *packetUnpacker) unpackLongHeaderPacket(opener handshake.LongHeaderOpener, hdr *wire.Header, data []byte, v protocol.Version) (*wire.ExtendedHeader, []byte, error) {
	extHdr, parseErr := u.unpackLongHeader(opener, hdr, data, v)
	// If the reserved bits are set incorrectly, we still need to continue unpacking.
	// This avoids a timing side-channel, which otherwise might allow an attacker
	// to gain information about the header encryption.
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, nil, parseErr
	}
	extHdrLen := extHdr.ParsedLen()
	extHdr.PacketNumber = opener.DecodePacketNumber(extHdr.PacketNumber, extHdr.PacketNumberLen)
	crypto_settings.Crypto_debug_println("Long header opener.Open(...) type: ", reflect.TypeOf(opener))
	decrypted, err := opener.Open(data[extHdrLen:extHdrLen], data[extHdrLen:], extHdr.PacketNumber, data[:extHdrLen])
	if err != nil {
		return nil, nil, err
	}
	if parseErr != nil {
		return nil, nil, parseErr
	}
	return extHdr, decrypted, nil
}

func (u *packetUnpacker) unpackShortHeaderPacket(opener handshake.ShortHeaderOpener, rcvTime time.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
	l, pn, pnLen, kp, parseErr := u.unpackShortHeader(opener, data)

	// If the reserved bits are set incorrectly, we still need to continue unpacking.
	// This avoids a timing side-channel, which otherwise might allow an attacker
	// to gain information about the header encryption.
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return 0, 0, 0, nil, &headerParseError{parseErr}
	}
	pn = opener.DecodePacketNumber(pn, pnLen)

	// length := 40
	// crypto_settings.Crypto_debug_println("\n\nRECEIVER: raw undecrypted (pn: ", pn, ")")
	// crypto_settings.Crypto_debug_println(hex.Dump(data[:length])) // TODO: remove
	// crypto_settings.Crypto_debug_println("type", reflect.TypeOf(opener))

	decrypted := data[l:]
	var err error
	if true || !crypto_turnoff.INCOMING_SHORT_HEADER_CRYPTO_TURNED_OFF { // ! TODO: crypto_turnoff check might be wrong position here?
		decrypted, err = opener.Open(data[l:l], data[l:], rcvTime, pn, kp, data[:l])
		if err != nil {
			return 0, 0, 0, nil, err
		}

		if crypto_settings.RegisterFullyReceivedPacket != nil {
			crypto_settings.RegisterFullyReceivedPacket(uint64(pn))
		}
	}

	// crypto_settings.Crypto_debug_println("\n\nRECEIVER: raw decrypted")
	// crypto_settings.Crypto_debug_println(hex.Dump(decrypted[:length])) // TODO: remove

	return pn, pnLen, kp, decrypted, parseErr
}

func (u *packetUnpacker) unpackShortHeader(hd headerDecryptor, data []byte) (int, protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, error) {
	hdrLen := 1 /* first header byte */ + u.shortHdrConnIDLen

	// NO_CRYPTO_TAG
	// here the offset for checking if a packet is too small
	// is different since no crypto overhead is in the data
	offset := 0
	if !crypto_turnoff.CRYPTO_TURNED_OFF {
		offset = 16
	}
	if len(data) < hdrLen+4+offset {
		return 0, 0, 0, 0, fmt.Errorf("packet too small, expected at least 20 bytes after the header, got %d", len(data)-hdrLen)
	}

	origPNBytes := make([]byte, 4)
	copy(origPNBytes, data[hdrLen:hdrLen+4])
	// 2. decrypt the header, assuming a 4 byte packet number
	hd.DecryptHeader(
		// here the (in case of no crypto) wrong offsed does not matter since DecryptHeader will not have an effect
		data[hdrLen+4:hdrLen+4+offset],
		&data[0],
		data[hdrLen:hdrLen+4],
	)
	// 3. parse the header (and learn the actual length of the packet number)
	l, pn, pnLen, kp, parseErr := wire.ParseShortHeader(data, u.shortHdrConnIDLen)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return l, pn, pnLen, kp, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if pnLen != protocol.PacketNumberLen4 {
		copy(data[hdrLen+int(pnLen):hdrLen+4], origPNBytes[int(pnLen):])
	}
	return l, pn, pnLen, kp, parseErr
}

// The error is either nil, a wire.ErrInvalidReservedBits or of type headerParseError.
func (u *packetUnpacker) unpackLongHeader(hd headerDecryptor, hdr *wire.Header, data []byte, v protocol.Version) (*wire.ExtendedHeader, error) {
	extHdr, err := unpackLongHeader(hd, hdr, data, v)
	if err != nil && err != wire.ErrInvalidReservedBits {
		return nil, &headerParseError{err: err}
	}
	return extHdr, err
}

func unpackLongHeader(hd headerDecryptor, hdr *wire.Header, data []byte, v protocol.Version) (*wire.ExtendedHeader, error) {
	r := bytes.NewReader(data)

	// NO_CRYPTO_TAG
	// here the offset for checking if a packet is too small
	// is different since no crypto overhead is in the data
	offset := 0
	if !crypto_turnoff.CRYPTO_TURNED_OFF {
		offset = 16
	}

	hdrLen := hdr.ParsedLen()
	if protocol.ByteCount(len(data)) < hdrLen+4+protocol.ByteCount(offset) {
		//nolint:stylecheck
		return nil, fmt.Errorf("Packet too small. Expected at least 20 bytes after the header, got %d", protocol.ByteCount(len(data))-hdrLen)
	}
	// The packet number can be up to 4 bytes long, but we won't know the length until we decrypt it.
	// 1. save a copy of the 4 bytes
	origPNBytes := make([]byte, 4)
	copy(origPNBytes, data[hdrLen:hdrLen+4])
	// 2. decrypt the header, assuming a 4 byte packet number
	hd.DecryptHeader(
		data[hdrLen+4:hdrLen+4+protocol.ByteCount(offset)],
		&data[0],
		data[hdrLen:hdrLen+4],
	)
	// 3. parse the header (and learn the actual length of the packet number)
	extHdr, parseErr := hdr.ParseExtended(r, v)
	if parseErr != nil && parseErr != wire.ErrInvalidReservedBits {
		return nil, parseErr
	}
	// 4. if the packet number is shorter than 4 bytes, replace the remaining bytes with the copy we saved earlier
	if extHdr.PacketNumberLen != protocol.PacketNumberLen4 {
		copy(data[extHdr.ParsedLen():hdrLen+4], origPNBytes[int(extHdr.PacketNumberLen):])
	}
	return extHdr, parseErr
}

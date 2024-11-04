package protocol

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

var ErrInvalidConnectionIDLen = errors.New("invalid Connection ID length")

// An ArbitraryLenConnectionID is a QUIC Connection ID able to represent Connection IDs according to RFC 8999.
// Future QUIC versions might allow connection ID lengths up to 255 bytes, while QUIC v1
// restricts the length to 20 bytes.
type ArbitraryLenConnectionID []byte

// PRIO_PACKS_TAG
const PriorityConnIDLen uint8 = 16

func (c ArbitraryLenConnectionID) Len() int {
	return len(c)
}

func (c ArbitraryLenConnectionID) Bytes() []byte {
	return c
}

func (c ArbitraryLenConnectionID) String() string {
	if c.Len() == 0 {
		return "(empty)"
	}
	return fmt.Sprintf("%x", c.Bytes())
}

const maxConnectionIDLen = 20

// A ConnectionID in QUIC
type ConnectionID struct {
	b [20]byte
	l uint8
}

// GenerateConnectionID generates a connection ID using cryptographic random
func GenerateConnectionID(l int) (ConnectionID, error) {
	var c ConnectionID
	c.l = uint8(l)
	_, err := rand.Read(c.b[:l])
	return c, err
}

// ParseConnectionID interprets b as a Connection ID.
// It panics if b is longer than 20 bytes.
func ParseConnectionID(b []byte) ConnectionID {
	if len(b) > maxConnectionIDLen {
		panic("invalid conn id length")
	}
	var c ConnectionID
	c.l = uint8(len(b))
	copy(c.b[:c.l], b)
	return c
}

// GenerateConnectionIDForInitial generates a connection ID for the Initial packet.
// It uses a length randomly chosen between 8 and 20 bytes.
func GenerateConnectionIDForInitial() (ConnectionID, error) {
	// r := make([]byte, 1)
	// if _, err := rand.Read(r); err != nil {
	// 	return ConnectionID{}, err
	// }
	// l := MinConnectionIDLenInitial + int(r[0])%(maxConnectionIDLen-MinConnectionIDLenInitial+1)

	// PRIO_PACKS_TAG
	l := int(PriorityConnIDLen)
	return GenerateConnectionID(l)
}

// ReadConnectionID reads a connection ID of length len from the given io.Reader.
// It returns io.EOF if there are not enough bytes to read.
func ReadConnectionID(r io.Reader, l int) (ConnectionID, error) {
	var c ConnectionID
	if l == 0 {
		return c, nil
	}
	if l > maxConnectionIDLen {
		return c, ErrInvalidConnectionIDLen
	}
	c.l = uint8(l)
	_, err := io.ReadFull(r, c.b[:l])
	if err == io.ErrUnexpectedEOF {
		return c, io.EOF
	}
	return c, err
}

// Len returns the length of the connection ID in bytes
func (c ConnectionID) Len() int {
	return int(c.l)
}

// Bytes returns the byte representation
func (c ConnectionID) Bytes() []byte {
	return c.b[:c.l]
}

func (c ConnectionID) String() string {
	if c.Len() == 0 {
		return "(empty)"
	}
	return fmt.Sprintf("%x", c.Bytes())
}

type DefaultConnectionIDGenerator struct {
	ConnLen int
}

func (d *DefaultConnectionIDGenerator) GenerateConnectionID() (ConnectionID, error) {
	return GenerateConnectionID(d.ConnLen)
}

func (d *DefaultConnectionIDGenerator) ConnectionIDLen() int {
	return d.ConnLen
}

// PRIO_PACKS_TAG
type PriorityConnectionIDGenerator struct {
	ConnLen            int
	NumberOfPriorities int
	PriorityCounter    int8
	NextPriority       int8
	NextPriorityValid  bool
}

func (t *PriorityConnectionIDGenerator) GenerateConnectionID() (ConnectionID, error) {

	// PRIO_PACKS_TAG
	// TODOME: better way than casting?
	if t.ConnLen != int(PriorityConnIDLen) {
		//fmt.Println("Priority-Connection ID length is not 16")
		return ConnectionID{}, ErrInvalidConnectionIDLen
	}

	// PRIO_PACKS_TAG
	// this part is for specifically setting the next priority
	// which is used in the case that an older connection ID is
	// retired and a new one with the same priority is needed
	if t.NextPriorityValid {
		t.PriorityCounter = t.NextPriority
		t.NextPriorityValid = false
	}

	var c ConnectionID
	c.l = uint8(t.ConnLen)
	_, err := rand.Read(c.b[1:t.ConnLen])
	if err != nil {
		return c, err
	}

	// add priority counter as the first byte of the connection ID and
	c.b[0] = byte(t.PriorityCounter)

	// first modulo, then increment since 0 is encoding for NoPriority and
	// actual priorities start at 1 and go up to NumberOfPriorities
	t.PriorityCounter = (t.PriorityCounter % int8(t.NumberOfPriorities)) + 1
	return c, nil
}

func (t *PriorityConnectionIDGenerator) ConnectionIDLen() int {
	return t.ConnLen
}

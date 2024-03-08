// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/danielpfeifer02/quic-go-prio-packs/internal/handshake (interfaces: LongHeaderOpener)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package mocks -destination long_header_opener.go github.com/danielpfeifer02/quic-go-prio-packs/internal/handshake LongHeaderOpener
//
// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	protocol "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	gomock "go.uber.org/mock/gomock"
)

// MockLongHeaderOpener is a mock of LongHeaderOpener interface.
type MockLongHeaderOpener struct {
	ctrl     *gomock.Controller
	recorder *MockLongHeaderOpenerMockRecorder
}

// MockLongHeaderOpenerMockRecorder is the mock recorder for MockLongHeaderOpener.
type MockLongHeaderOpenerMockRecorder struct {
	mock *MockLongHeaderOpener
}

// NewMockLongHeaderOpener creates a new mock instance.
func NewMockLongHeaderOpener(ctrl *gomock.Controller) *MockLongHeaderOpener {
	mock := &MockLongHeaderOpener{ctrl: ctrl}
	mock.recorder = &MockLongHeaderOpenerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockLongHeaderOpener) EXPECT() *MockLongHeaderOpenerMockRecorder {
	return m.recorder
}

// DecodePacketNumber mocks base method.
func (m *MockLongHeaderOpener) DecodePacketNumber(arg0 protocol.PacketNumber, arg1 protocol.PacketNumberLen) protocol.PacketNumber {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DecodePacketNumber", arg0, arg1)
	ret0, _ := ret[0].(protocol.PacketNumber)
	return ret0
}

// DecodePacketNumber indicates an expected call of DecodePacketNumber.
func (mr *MockLongHeaderOpenerMockRecorder) DecodePacketNumber(arg0, arg1 any) *LongHeaderOpenerDecodePacketNumberCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecodePacketNumber", reflect.TypeOf((*MockLongHeaderOpener)(nil).DecodePacketNumber), arg0, arg1)
	return &LongHeaderOpenerDecodePacketNumberCall{Call: call}
}

// LongHeaderOpenerDecodePacketNumberCall wrap *gomock.Call
type LongHeaderOpenerDecodePacketNumberCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *LongHeaderOpenerDecodePacketNumberCall) Return(arg0 protocol.PacketNumber) *LongHeaderOpenerDecodePacketNumberCall {
	c.Call = c.Call.Return(arg0)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *LongHeaderOpenerDecodePacketNumberCall) Do(f func(protocol.PacketNumber, protocol.PacketNumberLen) protocol.PacketNumber) *LongHeaderOpenerDecodePacketNumberCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *LongHeaderOpenerDecodePacketNumberCall) DoAndReturn(f func(protocol.PacketNumber, protocol.PacketNumberLen) protocol.PacketNumber) *LongHeaderOpenerDecodePacketNumberCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// DecryptHeader mocks base method.
func (m *MockLongHeaderOpener) DecryptHeader(arg0 []byte, arg1 *byte, arg2 []byte) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "DecryptHeader", arg0, arg1, arg2)
}

// DecryptHeader indicates an expected call of DecryptHeader.
func (mr *MockLongHeaderOpenerMockRecorder) DecryptHeader(arg0, arg1, arg2 any) *LongHeaderOpenerDecryptHeaderCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DecryptHeader", reflect.TypeOf((*MockLongHeaderOpener)(nil).DecryptHeader), arg0, arg1, arg2)
	return &LongHeaderOpenerDecryptHeaderCall{Call: call}
}

// LongHeaderOpenerDecryptHeaderCall wrap *gomock.Call
type LongHeaderOpenerDecryptHeaderCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *LongHeaderOpenerDecryptHeaderCall) Return() *LongHeaderOpenerDecryptHeaderCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *LongHeaderOpenerDecryptHeaderCall) Do(f func([]byte, *byte, []byte)) *LongHeaderOpenerDecryptHeaderCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *LongHeaderOpenerDecryptHeaderCall) DoAndReturn(f func([]byte, *byte, []byte)) *LongHeaderOpenerDecryptHeaderCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// Open mocks base method.
func (m *MockLongHeaderOpener) Open(arg0, arg1 []byte, arg2 protocol.PacketNumber, arg3 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Open", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Open indicates an expected call of Open.
func (mr *MockLongHeaderOpenerMockRecorder) Open(arg0, arg1, arg2, arg3 any) *LongHeaderOpenerOpenCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Open", reflect.TypeOf((*MockLongHeaderOpener)(nil).Open), arg0, arg1, arg2, arg3)
	return &LongHeaderOpenerOpenCall{Call: call}
}

// LongHeaderOpenerOpenCall wrap *gomock.Call
type LongHeaderOpenerOpenCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *LongHeaderOpenerOpenCall) Return(arg0 []byte, arg1 error) *LongHeaderOpenerOpenCall {
	c.Call = c.Call.Return(arg0, arg1)
	return c
}

// Do rewrite *gomock.Call.Do
func (c *LongHeaderOpenerOpenCall) Do(f func([]byte, []byte, protocol.PacketNumber, []byte) ([]byte, error)) *LongHeaderOpenerOpenCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *LongHeaderOpenerOpenCall) DoAndReturn(f func([]byte, []byte, protocol.PacketNumber, []byte) ([]byte, error)) *LongHeaderOpenerOpenCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

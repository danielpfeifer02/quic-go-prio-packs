// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/danielpfeifer02/quic-go-prio-packs (interfaces: StreamSender)
//
// Generated by this command:
//
//	mockgen -typed -build_flags=-tags=gomock -package quic -self_package github.com/danielpfeifer02/quic-go-prio-packs -destination mock_stream_sender_test.go github.com/danielpfeifer02/quic-go-prio-packs StreamSender
//
// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	protocol "github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	wire "github.com/danielpfeifer02/quic-go-prio-packs/internal/wire"
	gomock "go.uber.org/mock/gomock"
)

// MockStreamSender is a mock of StreamSender interface.
type MockStreamSender struct {
	ctrl     *gomock.Controller
	recorder *MockStreamSenderMockRecorder
}

// MockStreamSenderMockRecorder is the mock recorder for MockStreamSender.
type MockStreamSenderMockRecorder struct {
	mock *MockStreamSender
}

// NewMockStreamSender creates a new mock instance.
func NewMockStreamSender(ctrl *gomock.Controller) *MockStreamSender {
	mock := &MockStreamSender{ctrl: ctrl}
	mock.recorder = &MockStreamSenderMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockStreamSender) EXPECT() *MockStreamSenderMockRecorder {
	return m.recorder
}

// onHasStreamData mocks base method.
func (m *MockStreamSender) onHasStreamData(arg0 protocol.StreamID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "onHasStreamData", arg0)
}

// onHasStreamData indicates an expected call of onHasStreamData.
func (mr *MockStreamSenderMockRecorder) onHasStreamData(arg0 any) *StreamSenderonHasStreamDataCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "onHasStreamData", reflect.TypeOf((*MockStreamSender)(nil).onHasStreamData), arg0)
	return &StreamSenderonHasStreamDataCall{Call: call}
}

// StreamSenderonHasStreamDataCall wrap *gomock.Call
type StreamSenderonHasStreamDataCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamSenderonHasStreamDataCall) Return() *StreamSenderonHasStreamDataCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamSenderonHasStreamDataCall) Do(f func(protocol.StreamID)) *StreamSenderonHasStreamDataCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamSenderonHasStreamDataCall) DoAndReturn(f func(protocol.StreamID)) *StreamSenderonHasStreamDataCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// onStreamCompleted mocks base method.
func (m *MockStreamSender) onStreamCompleted(arg0 protocol.StreamID) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "onStreamCompleted", arg0)
}

// onStreamCompleted indicates an expected call of onStreamCompleted.
func (mr *MockStreamSenderMockRecorder) onStreamCompleted(arg0 any) *StreamSenderonStreamCompletedCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "onStreamCompleted", reflect.TypeOf((*MockStreamSender)(nil).onStreamCompleted), arg0)
	return &StreamSenderonStreamCompletedCall{Call: call}
}

// StreamSenderonStreamCompletedCall wrap *gomock.Call
type StreamSenderonStreamCompletedCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamSenderonStreamCompletedCall) Return() *StreamSenderonStreamCompletedCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamSenderonStreamCompletedCall) Do(f func(protocol.StreamID)) *StreamSenderonStreamCompletedCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamSenderonStreamCompletedCall) DoAndReturn(f func(protocol.StreamID)) *StreamSenderonStreamCompletedCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

// queueControlFrame mocks base method.
func (m *MockStreamSender) queueControlFrame(arg0 wire.Frame) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "queueControlFrame", arg0)
}

// queueControlFrame indicates an expected call of queueControlFrame.
func (mr *MockStreamSenderMockRecorder) queueControlFrame(arg0 any) *StreamSenderqueueControlFrameCall {
	mr.mock.ctrl.T.Helper()
	call := mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "queueControlFrame", reflect.TypeOf((*MockStreamSender)(nil).queueControlFrame), arg0)
	return &StreamSenderqueueControlFrameCall{Call: call}
}

// StreamSenderqueueControlFrameCall wrap *gomock.Call
type StreamSenderqueueControlFrameCall struct {
	*gomock.Call
}

// Return rewrite *gomock.Call.Return
func (c *StreamSenderqueueControlFrameCall) Return() *StreamSenderqueueControlFrameCall {
	c.Call = c.Call.Return()
	return c
}

// Do rewrite *gomock.Call.Do
func (c *StreamSenderqueueControlFrameCall) Do(f func(wire.Frame)) *StreamSenderqueueControlFrameCall {
	c.Call = c.Call.Do(f)
	return c
}

// DoAndReturn rewrite *gomock.Call.DoAndReturn
func (c *StreamSenderqueueControlFrameCall) DoAndReturn(f func(wire.Frame)) *StreamSenderqueueControlFrameCall {
	c.Call = c.Call.DoAndReturn(f)
	return c
}

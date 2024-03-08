package quic

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"github.com/danielpfeifer02/quic-go-prio-packs/internal/protocol"
	"github.com/danielpfeifer02/quic-go-prio-packs/internal/utils"
)

//go:generate sh -c "echo '// Code generated by go generate. DO NOT EDIT.\n// Source: sys_conn_buffers.go\n' > sys_conn_buffers_write.go && sed -e 's/SetReadBuffer/SetWriteBuffer/g' -e 's/setReceiveBuffer/setSendBuffer/g' -e 's/inspectReadBuffer/inspectWriteBuffer/g' -e 's/protocol\\.DesiredReceiveBufferSize/protocol\\.DesiredSendBufferSize/g' -e 's/forceSetReceiveBuffer/forceSetSendBuffer/g' -e 's/receive buffer/send buffer/g' sys_conn_buffers.go | sed '/^\\/\\/go:generate/d' >> sys_conn_buffers_write.go"
func setReceiveBuffer(c net.PacketConn) error {
	conn, ok := c.(interface{ SetReadBuffer(int) error })
	if !ok {
		return errors.New("connection doesn't allow setting of receive buffer size. Not a *net.UDPConn?")
	}

	var syscallConn syscall.RawConn
	if sc, ok := c.(interface {
		SyscallConn() (syscall.RawConn, error)
	}); ok {
		var err error
		syscallConn, err = sc.SyscallConn()
		if err != nil {
			syscallConn = nil
		}
	}
	// The connection has a SetReadBuffer method, but we couldn't obtain a syscall.RawConn.
	// This shouldn't happen for a net.UDPConn, but is possible if the connection just implements the
	// net.PacketConn interface and the SetReadBuffer method.
	// We have no way of checking if increasing the buffer size actually worked.
	if syscallConn == nil {
		return conn.SetReadBuffer(protocol.DesiredReceiveBufferSize)
	}

	size, err := inspectReadBuffer(syscallConn)
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if size >= protocol.DesiredReceiveBufferSize {
		utils.DefaultLogger.Debugf("Conn has receive buffer of %d kiB (wanted: at least %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024)
		return nil
	}
	// Ignore the error. We check if we succeeded by querying the buffer size afterward.
	_ = conn.SetReadBuffer(protocol.DesiredReceiveBufferSize)
	newSize, err := inspectReadBuffer(syscallConn)
	if newSize < protocol.DesiredReceiveBufferSize {
		// Try again with RCVBUFFORCE on Linux
		_ = forceSetReceiveBuffer(syscallConn, protocol.DesiredReceiveBufferSize)
		newSize, err = inspectReadBuffer(syscallConn)
		if err != nil {
			return fmt.Errorf("failed to determine receive buffer size: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to determine receive buffer size: %w", err)
	}
	if newSize == size {
		return fmt.Errorf("failed to increase receive buffer size (wanted: %d kiB, got %d kiB)", protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	if newSize < protocol.DesiredReceiveBufferSize {
		return fmt.Errorf("failed to sufficiently increase receive buffer size (was: %d kiB, wanted: %d kiB, got: %d kiB)", size/1024, protocol.DesiredReceiveBufferSize/1024, newSize/1024)
	}
	utils.DefaultLogger.Debugf("Increased receive buffer size to %d kiB", newSize/1024)
	return nil
}

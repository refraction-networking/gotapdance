package tapdance

import (
	"net"
	"time"
	"errors"
)

type tapdanceConn struct {
	writerConn net.Conn
	readerConn net.Conn
}

func DialTapDance(
id uint64,
customDialer func(string, string) (net.Conn, error)) (tdConn *tapdanceConn, err error) {
	tdConn = new(tapdanceConn)
	tdConn.readerConn, err = dialRWTapDance(id, customDialer())
	tdConn.writerConn = tdConn.readerConn
	return
}

// Read reads data from the connection.
// Read can be made to time out and return an Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetReadDeadline.
func (tdConn *tapdanceConn) Read(b []byte) (n int, err error) {
	return tdConn.readerConn.Read(b)
}

	// Write writes data to the connection.
	// Write can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (tdConn *tapdanceConn) Write(b []byte) (n int, err error) {
	return tdConn.writerConn.Write(b)
}

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
func (tdConn *tapdanceConn) Close() error {
	// TODO
	defer tdConn.readerConn.Close()
	return tdConn.writerConn.Close()
}

	// LocalAddr returns the local network address.
func (tdConn *tapdanceConn) LocalAddr() net.Addr {
	return nil // TODO
}

	// RemoteAddr returns the remote network address.
func (tdConn *tapdanceConn) RemoteAddr() net.Addr {
	return nil // TODO
}

	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail with a timeout (see type Error) instead of
	// blocking. The deadline applies to all future and pending
	// I/O, not just the immediately following call to Read or
	// Write. After a deadline has been exceeded, the connection
	// can be refreshed by setting a deadline in the future.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful Read or Write calls.
	//
	// A zero value for t means I/O operations will not time out.
func (tdConn *tapdanceConn) SetDeadline(t time.Time) error {
	return errors.New("Not implemented") // TODO
}

	// SetReadDeadline sets the deadline for future Read calls
	// and any currently-blocked Read call.
	// A zero value for t means Read will not time out.
func (tdConn *tapdanceConn) SetReadDeadline(t time.Time) error {
	return errors.New("Not implemented") // TODO
}

	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
func (tdConn *tapdanceConn) SetWriteDeadline(t time.Time) error {
	return errors.New("Not implemented") // TODO
}

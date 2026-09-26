package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
)

// SSHInspector inspects SSH connections at the protocol level.
type SSHInspector struct{}

// SSHResult is the outcome of SSHInspector.Inspect.
type SSHResult struct {
	ClientVersion string // e.g. "SSH-2.0-OpenSSH_8.9"
	IsSSH1        bool   // true if client advertises SSH-1.x
	Valid         bool
}

// Inspect reads the SSH client banner from conn.
func (SSHInspector) Inspect(conn net.Conn) (*bufio.Reader, SSHResult) {
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return br, SSHResult{}
	}
	line = strings.TrimSpace(line)

	result := SSHResult{
		ClientVersion: line,
		Valid:         strings.HasPrefix(line, "SSH-"),
	}
	if strings.HasPrefix(line, "SSH-1.") {
		result.IsSSH1 = true
	}
	return br, result
}

// SSHAuthMonitor wraps an upstream connection and watches the proxied byte stream
// for SSH_MSG_USERAUTH_FAILURE messages (message type 51).
type SSHAuthMonitor struct {
	AuthFailures int
	onFailure    func()
}

// NewSSHAuthMonitor returns a monitor that calls onFailure on each detected auth failure.
func NewSSHAuthMonitor(onFailure func()) *SSHAuthMonitor {
	return &SSHAuthMonitor{onFailure: onFailure}
}

// WrapUpstream wraps the upstream connection to scan outgoing packets.
func (m *SSHAuthMonitor) WrapUpstream(upstream net.Conn) net.Conn {
	return &sshMonitorConn{Conn: upstream, monitor: m}
}

type sshMonitorConn struct {
	net.Conn
	monitor *SSHAuthMonitor
	buf     []byte
}

func (c *sshMonitorConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.buf = append(c.buf, p[:n]...)
		c.scan()
	}
	return n, err
}

// CloseWrite forwards half-close to the underlying Conn if supported.
func (c *sshMonitorConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *sshMonitorConn) scan() {
	for len(c.buf) >= 6 {
		pktLen := int(c.buf[0])<<24 | int(c.buf[1])<<16 | int(c.buf[2])<<8 | int(c.buf[3])
		if pktLen < 2 || pktLen > 35000 {
			c.buf = c.buf[1:] // resync
			continue
		}
		total := 4 + pktLen
		if len(c.buf) < total {
			break // wait for more data
		}
		msgType := c.buf[5]

		const sshMsgUserAuthFailure = 51
		if msgType == sshMsgUserAuthFailure {
			c.monitor.AuthFailures++
			if c.monitor.onFailure != nil {
				c.monitor.onFailure()
			}
		}
		c.buf = c.buf[total:]
	}
	if len(c.buf) > 65536 {
		c.buf = c.buf[len(c.buf)-65536:]
	}
}

// RejectSSH1 sends a polite SSH-2.0 banner and disconnect packet.
func RejectSSH1(conn net.Conn) {
	banner := "SSH-2.0-RouteWarden_TCP_Warden\r\n"
	conn.Write([]byte(banner))
	msg := buildSSHDisconnect(7, "SSH-1.x not supported")
	conn.Write(msg)
	conn.Close()
}

// RejectSSH sends a disconnect message and closes the connection.
func RejectSSH(conn net.Conn, reason string) {
	conn.Write([]byte("SSH-2.0-RouteWarden_TCP_Warden\r\n"))
	msg := buildSSHDisconnect(11, reason)
	conn.Write(msg)
	conn.Close()
}

func buildSSHDisconnect(code uint32, message string) []byte {
	msgLen := 1 + 4 + 4 + len(message) + 4
	totalNoPadding := 4 + 1 + msgLen
	rem := totalNoPadding % 8
	padding := 8 - rem
	if padding < 4 {
		padding += 8
	}
	pktLen := 1 + msgLen + padding

	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%c%c%c%c",
		byte(pktLen>>24), byte(pktLen>>16), byte(pktLen>>8), byte(pktLen))
	buf.WriteByte(byte(padding))
	buf.WriteByte(1) // SSH_MSG_DISCONNECT
	fmt.Fprintf(buf, "%c%c%c%c",
		byte(code>>24), byte(code>>16), byte(code>>8), byte(code))
	mlen := uint32(len(message))
	fmt.Fprintf(buf, "%c%c%c%c", byte(mlen>>24), byte(mlen>>16), byte(mlen>>8), byte(mlen))
	buf.WriteString(message)
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write(make([]byte, padding))

	return buf.Bytes()
}

package ftp

import (
	"bufio"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects FTP wire sessions (RFC 959).
type Inspector struct {
	MaxAuthFailures int
}

// Run executes the FTP inspection and relay loop.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	var bytesIn atomic.Int64
	var bytesOut atomic.Int64

	result := func(err error) sdk.ProxyResult {
		return sdk.ProxyResult{
			BytesIn:  bytesIn.Load(),
			BytesOut: bytesOut.Load(),
			Err:      err,
		}
	}

	clientReader := bufio.NewReader(client)
	upstreamReader := bufio.NewReader(upstream)

	// 1. Read upstream server greeting (e.g. 220 Service ready)
	greeting, err := readFTPResponse(upstreamReader)
	if err != nil {
		return result(err), true, "failed reading FTP greeting: " + err.Error(), err
	}
	bytesOut.Add(int64(len(greeting)))
	if _, err := client.Write([]byte(greeting)); err != nil {
		return result(err), false, "", err
	}

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		clientLine, err := clientReader.ReadString('\n')
		if err != nil {
			return result(err), false, "", nil
		}
		bytesIn.Add(int64(len(clientLine)))

		trimmed := strings.TrimSpace(clientLine)
		upper := strings.ToUpper(trimmed)

		// Forward command to upstream
		upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := upstream.Write([]byte(clientLine)); err != nil {
			return result(err), false, "", nil
		}

		// Read upstream response
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		serverResp, err := readFTPResponse(upstreamReader)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(serverResp)))

		// Check for AUTH TLS / AUTH SSL handover
		if strings.HasPrefix(upper, "AUTH TLS") || strings.HasPrefix(upper, "AUTH SSL") {
			if _, err := client.Write([]byte(serverResp)); err != nil {
				return result(err), false, "", nil
			}
			if strings.HasPrefix(serverResp, "234") {
				client.SetDeadline(time.Time{})
				upstream.SetDeadline(time.Time{})
				proxyRes := protocol.Proxy(client, upstream)
				bytesIn.Add(proxyRes.BytesIn)
				bytesOut.Add(proxyRes.BytesOut)
				return result(nil), false, "", nil
			}
			continue
		}

		// Check for authentication failure on PASS command
		if strings.HasPrefix(upper, "PASS ") || upper == "PASS" {
			if strings.HasPrefix(serverResp, "530") {
				if ctx != nil {
					ctx.OnAuthFailure()
					ctx.OnSecurityEvent("auth_failure", "ftp_login_failed")
				}
			}
		}

		// Forward upstream response to client
		client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := client.Write([]byte(serverResp)); err != nil {
			return result(err), false, "", nil
		}

		if upper == "QUIT" {
			return result(nil), false, "", nil
		}
	}
}

func readFTPResponse(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return sb.String(), err
		}
		sb.WriteString(line)
		if len(line) >= 4 && line[3] == ' ' && isDigit(line[0]) && isDigit(line[1]) && isDigit(line[2]) {
			break
		}
	}
	return sb.String(), nil
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

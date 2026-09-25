package echo_filter

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects payloads for banned keywords or exploit signatures.
type Inspector struct {
	BannedKeywords []string
}

// Run inspects initial payload and proxies the session if clean.
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

	// Peek at initial client data up to 4096 bytes
	client.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil && err != io.EOF {
		return result(err), false, "", err
	}
	bytesIn.Add(int64(n))

	payload := string(buf[:n])
	upperPayload := strings.ToUpper(payload)

	// Check for banned keywords
	for _, kw := range insp.BannedKeywords {
		kwUpper := strings.ToUpper(strings.TrimSpace(kw))
		if kwUpper != "" && strings.Contains(upperPayload, kwUpper) {
			rejection := fmt.Sprintf("ROUTEWARDEN_BLOCKED: payload contains prohibited keyword %q\r\n", kw)
			client.Write([]byte(rejection))
			bytesOut.Add(int64(len(rejection)))
			if ctx != nil {
				ctx.OnSecurityEvent("blocked", "banned_keyword_"+kwUpper)
			}
			return result(nil), true, fmt.Sprintf("payload contains banned keyword: %s", kw), nil
		}
	}

	// Replay peeked bytes into upstream and switch to raw proxy
	upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if n > 0 {
		if _, err := upstream.Write(buf[:n]); err != nil {
			return result(err), false, "", err
		}
		bytesOut.Add(int64(n))
	}

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	bufferedClient := &protocol.BufferedConn{
		Reader: bytes.NewReader(nil),
		Conn:   client,
	}

	proxyRes := protocol.Proxy(bufferedClient, upstream)
	bytesIn.Add(proxyRes.BytesIn)
	bytesOut.Add(proxyRes.BytesOut)

	return result(proxyRes.Err), false, "", nil
}

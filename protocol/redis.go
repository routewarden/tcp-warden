package protocol

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// RedisInspectorOptions configures Redis protocol inspection.
type RedisInspectorOptions struct {
	OnAuthFailure   func()
	BlockedCommands []string // e.g. ["FLUSHALL", "FLUSHDB", "KEYS", "CONFIG", "SHUTDOWN", "DEBUG"]
}

// RedisProxy inspects and relays Redis wire protocol (RESP).
type RedisProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     RedisInspectorOptions

	blockedMap map[string]struct{}
	bytesIn    atomic.Int64
	bytesOut   atomic.Int64
}

// NewRedisProxy creates a new RedisProxy session.
func NewRedisProxy(client, upstream net.Conn, opts RedisInspectorOptions) *RedisProxy {
	bMap := make(map[string]struct{})
	for _, cmd := range opts.BlockedCommands {
		bMap[strings.ToUpper(strings.TrimSpace(cmd))] = struct{}{}
	}
	return &RedisProxy{
		client:     client,
		upstream:   upstream,
		opts:       opts,
		blockedMap: bMap,
	}
}

// Run executes the Redis protocol command inspection loop.
func (p *RedisProxy) Run() (ProxyResult, bool, string) {
	clientReader := bufio.NewReader(p.client)
	upstreamReader := bufio.NewReader(p.upstream)

	for {
		p.client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		cmdName, rawCmdBytes, err := readRedisCommand(clientReader)
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesIn.Add(int64(len(rawCmdBytes)))

		upperCmd := strings.ToUpper(cmdName)

		// 1. Check blocked commands
		if _, isBlocked := p.blockedMap[upperCmd]; isBlocked {
			errMsg := fmt.Sprintf("-ERR command '%s' is blocked by RouteWarden\r\n", upperCmd)
			p.client.Write([]byte(errMsg))
			p.bytesOut.Add(int64(len(errMsg)))
			return p.result(), true, fmt.Sprintf("blocked redis command: %s", upperCmd)
		}

		// 2. Forward command to upstream
		p.upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := p.upstream.Write(rawCmdBytes); err != nil {
			return p.result(), false, ""
		}

		// 3. Read response from upstream and check for auth errors
		p.upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		respBytes, err := readRedisResponse(upstreamReader)
		if err != nil {
			return p.result(), false, ""
		}
		p.bytesOut.Add(int64(len(respBytes)))

		if upperCmd == "AUTH" {
			respStr := string(respBytes)
			if strings.HasPrefix(respStr, "-WRONGPASS") ||
				strings.HasPrefix(respStr, "-ERR invalid password") ||
				strings.Contains(strings.ToLower(respStr), "authentication failed") {
				if p.opts.OnAuthFailure != nil {
					p.opts.OnAuthFailure()
				}
			}
		}

		// Forward response to client
		p.client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := p.client.Write(respBytes); err != nil {
			return p.result(), false, ""
		}
	}
}

func (p *RedisProxy) result() ProxyResult {
	return ProxyResult{
		BytesIn:  p.bytesIn.Load(),
		BytesOut: p.bytesOut.Load(),
	}
}

// readRedisCommand parses a RESP command array or inline command and returns (commandName, rawBytes, error).
func readRedisCommand(r *bufio.Reader) (string, []byte, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	raw := []byte(line)

	trimmed := strings.TrimRight(line, "\r\n")
	if len(trimmed) == 0 {
		return "", raw, nil
	}

	// RESP Array: *<count>\r\n
	if trimmed[0] == '*' {
		count, err := strconv.Atoi(trimmed[1:])
		if err != nil || count <= 0 {
			return "", raw, nil
		}

		var cmdName string
		for i := 0; i < count; i++ {
			// Read $<len>\r\n
			lenLine, err := r.ReadString('\n')
			if err != nil {
				return "", raw, err
			}
			raw = append(raw, lenLine...)
			lenTrimmed := strings.TrimRight(lenLine, "\r\n")
			if len(lenTrimmed) > 0 && lenTrimmed[0] == '$' {
				argLen, err := strconv.Atoi(lenTrimmed[1:])
				if err == nil && argLen >= 0 {
					argData := make([]byte, argLen+2) // data + \r\n
					if _, err := r.Read(argData); err != nil {
						return "", raw, err
					}
					raw = append(raw, argData...)
					if i == 0 {
						cmdName = strings.TrimRight(string(argData), "\r\n")
					}
				}
			}
		}
		return cmdName, raw, nil
	}

	// Inline command: e.g. "AUTH secret\r\n" or "PING\r\n"
	parts := strings.Fields(trimmed)
	if len(parts) > 0 {
		return parts[0], raw, nil
	}
	return "", raw, nil
}

// readRedisResponse reads a single complete RESP response value from upstream.
func readRedisResponse(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	resp := []byte(line)
	if len(line) == 0 {
		return resp, nil
	}

	switch line[0] {
	case '+', '-', ':': // Simple string, error, integer
		return resp, nil
	case '$': // Bulk string: $<len>\r\n<data>\r\n
		trimmed := strings.TrimRight(line[1:], "\r\n")
		argLen, err := strconv.Atoi(trimmed)
		if err != nil || argLen < 0 {
			// Null bulk string: $-1\r\n
			return resp, nil
		}
		body := make([]byte, argLen+2)
		if _, err := r.Read(body); err != nil {
			return resp, err
		}
		return append(resp, body...), nil
	case '*': // Array
		trimmed := strings.TrimRight(line[1:], "\r\n")
		count, err := strconv.Atoi(trimmed)
		if err != nil || count <= 0 {
			return resp, nil
		}
		for i := 0; i < count; i++ {
			sub, err := readRedisResponse(r)
			if err != nil {
				return resp, err
			}
			resp = append(resp, sub...)
		}
		return resp, nil
	}
	return resp, nil
}

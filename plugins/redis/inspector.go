package redis

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

// Inspector inspects Redis RESP protocol commands and responses.
type Inspector struct {
	BlockedCommands []string
	blockedMap      map[string]struct{}
}

// NewInspector creates an Inspector with precomputed command lookup map.
func NewInspector(blockedCmds []string) *Inspector {
	bMap := make(map[string]struct{})
	for _, cmd := range blockedCmds {
		bMap[strings.ToUpper(strings.TrimSpace(cmd))] = struct{}{}
	}
	return &Inspector{
		BlockedCommands: blockedCmds,
		blockedMap:      bMap,
	}
}

// Run executes the Redis protocol command inspection loop.
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

	for {
		client.SetReadDeadline(time.Now().Add(5 * time.Minute))
		cmdName, rawCmdBytes, err := readRedisCommand(clientReader)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesIn.Add(int64(len(rawCmdBytes)))

		upperCmd := strings.ToUpper(cmdName)

		// 1. Check blocked commands
		if _, isBlocked := insp.blockedMap[upperCmd]; isBlocked {
			errMsg := fmt.Sprintf("-ERR command '%s' is blocked by RouteWarden\r\n", upperCmd)
			client.Write([]byte(errMsg))
			bytesOut.Add(int64(len(errMsg)))
			if ctx != nil {
				ctx.OnSecurityEvent("blocked", "blocked_redis_command_"+upperCmd)
			}
			return result(nil), true, fmt.Sprintf("blocked redis command: %s", upperCmd), nil
		}

		// 2. Forward command to upstream
		upstream.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := upstream.Write(rawCmdBytes); err != nil {
			return result(err), false, "", nil
		}

		// 3. Read response from upstream and check for auth errors
		upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
		respBytes, err := readRedisResponse(upstreamReader)
		if err != nil {
			return result(err), false, "", nil
		}
		bytesOut.Add(int64(len(respBytes)))

		if upperCmd == "AUTH" {
			respStr := string(respBytes)
			if strings.HasPrefix(respStr, "-WRONGPASS") ||
				strings.HasPrefix(respStr, "-ERR invalid password") ||
				strings.Contains(strings.ToLower(respStr), "authentication failed") {
				if ctx != nil {
					ctx.OnAuthFailure()
					ctx.OnSecurityEvent("auth_failure", "redis_auth_failed")
				}
			}
		}

		// Forward response to client
		client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := client.Write(respBytes); err != nil {
			return result(err), false, "", nil
		}
	}
}

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

	if trimmed[0] == '*' {
		count, err := strconv.Atoi(trimmed[1:])
		if err != nil || count <= 0 {
			return "", raw, nil
		}

		var cmdName string
		for i := 0; i < count; i++ {
			lenLine, err := r.ReadString('\n')
			if err != nil {
				return "", raw, err
			}
			raw = append(raw, lenLine...)
			lenTrimmed := strings.TrimRight(lenLine, "\r\n")
			if len(lenTrimmed) > 0 && lenTrimmed[0] == '$' {
				argLen, err := strconv.Atoi(lenTrimmed[1:])
				if err == nil && argLen >= 0 {
					argData := make([]byte, argLen+2)
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

	parts := strings.Fields(trimmed)
	if len(parts) > 0 {
		return parts[0], raw, nil
	}
	return "", raw, nil
}

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
	case '+', '-', ':':
		return resp, nil
	case '$':
		trimmed := strings.TrimRight(line[1:], "\r\n")
		argLen, err := strconv.Atoi(trimmed)
		if err != nil || argLen < 0 {
			return resp, nil
		}
		body := make([]byte, argLen+2)
		if _, err := r.Read(body); err != nil {
			return resp, err
		}
		return append(resp, body...), nil
	case '*':
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

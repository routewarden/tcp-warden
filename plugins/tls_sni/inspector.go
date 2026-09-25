package tls_sni

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/routewarden/tcp-warden/plugins/sdk"
	"github.com/routewarden/tcp-warden/protocol"
)

// Inspector inspects TLS ClientHello to extract SNI and filter domains without decryption.
type Inspector struct {
	AllowedDomains []string
	BlockedDomains []string
}

// Run inspects the ClientHello SNI and relays encrypted TLS stream.
func (insp *Inspector) Run(ctx sdk.Context, client, upstream net.Conn) (sdk.ProxyResult, bool, string, error) {
	client.SetReadDeadline(time.Now().Add(10 * time.Second))

	var recordHeader [5]byte
	if _, err := io.ReadFull(client, recordHeader[:]); err != nil {
		return sdk.ProxyResult{}, true, "failed reading TLS record header: " + err.Error(), err
	}

	if recordHeader[0] != 0x16 {
		return sdk.ProxyResult{}, true, "not a TLS handshake record", nil
	}

	recordLen := int(recordHeader[3])<<8 | int(recordHeader[4])
	if recordLen <= 0 || recordLen > 16384 {
		return sdk.ProxyResult{}, true, "invalid TLS record length", nil
	}

	handshakePayload := make([]byte, recordLen)
	if _, err := io.ReadFull(client, handshakePayload); err != nil {
		return sdk.ProxyResult{}, true, "failed reading TLS handshake payload: " + err.Error(), err
	}

	sni, err := extractSNI(handshakePayload)
	if err != nil {
		sni = ""
	}

	if sni != "" {
		sniLower := strings.ToLower(sni)

		// 1. Blocked domains
		for _, blockedPattern := range insp.BlockedDomains {
			if matchDomain(sniLower, strings.ToLower(blockedPattern)) {
				if ctx != nil {
					ctx.OnSecurityEvent("blocked", "blocked_sni_domain_"+sni)
				}
				return sdk.ProxyResult{}, true, fmt.Sprintf("blocked SNI domain: %s (matches %s)", sni, blockedPattern), nil
			}
		}

		// 2. Allowed domains
		if len(insp.AllowedDomains) > 0 {
			matched := false
			for _, allowedPattern := range insp.AllowedDomains {
				if matchDomain(sniLower, strings.ToLower(allowedPattern)) {
					matched = true
					break
				}
			}
			if !matched {
				if ctx != nil {
					ctx.OnSecurityEvent("blocked", "sni_domain_not_allowed_"+sni)
				}
				return sdk.ProxyResult{}, true, fmt.Sprintf("SNI domain not allowed: %s", sni), nil
			}
		}
	}

	peeked := append(recordHeader[:], handshakePayload...)
	bufferedClient := &protocol.BufferedConn{
		Reader: io.MultiReader(bytes.NewReader(peeked), client),
		Conn:   client,
	}

	client.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	res := protocol.Proxy(bufferedClient, upstream)
	return sdk.ProxyResult{
		BytesIn:  res.BytesIn,
		BytesOut: res.BytesOut,
		Err:      res.Err,
	}, false, "", nil
}

func extractSNI(data []byte) (string, error) {
	if len(data) < 4 || data[0] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}

	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return "", fmt.Errorf("truncated ClientHello")
	}

	data = data[4 : 4+msgLen]
	if len(data) < 34 {
		return "", fmt.Errorf("ClientHello too short")
	}

	pos := 34

	if pos >= len(data) {
		return "", fmt.Errorf("truncated at session ID")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return "", fmt.Errorf("truncated at cipher suites")
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	if pos >= len(data) {
		return "", fmt.Errorf("truncated at compression methods")
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	if pos+2 > len(data) {
		return "", fmt.Errorf("no extensions present")
	}
	extensionsLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2

	if pos+extensionsLen > len(data) {
		return "", fmt.Errorf("truncated extensions")
	}

	extensions := data[pos : pos+extensionsLen]
	extPos := 0

	for extPos+4 <= len(extensions) {
		extType := int(extensions[extPos])<<8 | int(extensions[extPos+1])
		extLen := int(extensions[extPos+2])<<8 | int(extensions[extPos+3])
		extPos += 4

		if extPos+extLen > len(extensions) {
			break
		}

		if extType == 0x0000 {
			sniData := extensions[extPos : extPos+extLen]
			if len(sniData) < 2 {
				return "", fmt.Errorf("truncated SNI data")
			}
			listLen := int(sniData[0])<<8 | int(sniData[1])
			if len(sniData) < 2+listLen {
				return "", fmt.Errorf("truncated SNI list")
			}
			listData := sniData[2 : 2+listLen]

			listPos := 0
			for listPos+3 <= len(listData) {
				nameType := listData[listPos]
				nameLen := int(listData[listPos+1])<<8 | int(listData[listPos+2])
				listPos += 3

				if listPos+nameLen > len(listData) {
					break
				}

				if nameType == 0x00 {
					return string(listData[listPos : listPos+nameLen]), nil
				}
				listPos += nameLen
			}
		}
		extPos += extLen
	}

	return "", fmt.Errorf("SNI extension not found")
}

func matchDomain(domain, pattern string) bool {
	if domain == pattern {
		return true
	}
	matched, err := filepath.Match(pattern, domain)
	return err == nil && matched
}

package protocol

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"time"
)

// TLSInspectorOptions configures TLS SNI inspection.
type TLSInspectorOptions struct {
	AllowedDomains []string // Wildcard patterns allowed (e.g. "*.example.com", "app.local")
	BlockedDomains []string // Wildcard patterns blocked (e.g. "*.malicious.org", "phishing.com")
}

// TLSSNIProxy inspects the TLS ClientHello to extract SNI without decrypting the stream.
type TLSSNIProxy struct {
	client   net.Conn
	upstream net.Conn
	opts     TLSInspectorOptions
}

// NewTLSSNIProxy creates a new TLSSNIProxy session.
func NewTLSSNIProxy(client, upstream net.Conn, opts TLSInspectorOptions) *TLSSNIProxy {
	return &TLSSNIProxy{
		client:   client,
		upstream: upstream,
		opts:     opts,
	}
}

// Run inspects the ClientHello SNI and relays the encrypted TLS session to upstream.
func (p *TLSSNIProxy) Run() (ProxyResult, bool, string) {
	p.client.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Peek at the TLS record header (5 bytes)
	var recordHeader [5]byte
	if _, err := io.ReadFull(p.client, recordHeader[:]); err != nil {
		return ProxyResult{}, true, "failed reading TLS record header: " + err.Error()
	}

	// 0x16 = Handshake record
	if recordHeader[0] != 0x16 {
		return ProxyResult{}, true, "not a TLS handshake record"
	}

	recordLen := int(recordHeader[3])<<8 | int(recordHeader[4])
	if recordLen <= 0 || recordLen > 16384 {
		return ProxyResult{}, true, "invalid TLS record length"
	}

	handshakePayload := make([]byte, recordLen)
	if _, err := io.ReadFull(p.client, handshakePayload); err != nil {
		return ProxyResult{}, true, "failed reading TLS handshake payload: " + err.Error()
	}

	// Extract SNI
	sni, err := extractSNI(handshakePayload)
	if err != nil {
		// No SNI found or invalid ClientHello
		sni = ""
	}

	// Domain Filtering
	if len(p.opts.AllowedDomains) > 0 && sni == "" {
		return ProxyResult{}, true, "missing SNI in TLS ClientHello while domain allowlist is enforced"
	}

	if sni != "" {
		sniLower := strings.ToLower(sni)

		// 1. Check blocked domains
		for _, blockedPattern := range p.opts.BlockedDomains {
			if matchDomain(sniLower, strings.ToLower(blockedPattern)) {
				return ProxyResult{}, true, fmt.Sprintf("blocked SNI domain: %s (matches pattern %s)", sni, blockedPattern)
			}
		}

		// 2. Check allowed domains (if specified, must match at least one)
		if len(p.opts.AllowedDomains) > 0 {
			matched := false
			for _, allowedPattern := range p.opts.AllowedDomains {
				if matchDomain(sniLower, strings.ToLower(allowedPattern)) {
					matched = true
					break
				}
			}
			if !matched {
				return ProxyResult{}, true, fmt.Sprintf("SNI domain not allowed: %s", sni)
			}
		}
	}

	// Reassemble initial peeked bytes
	peeked := append(recordHeader[:], handshakePayload...)
	bufferedClient := &BufferedConn{
		Reader: io.MultiReader(bytes.NewReader(peeked), p.client),
		Conn:   p.client,
	}

	p.client.SetDeadline(time.Time{})
	p.upstream.SetDeadline(time.Time{})

	res := Proxy(bufferedClient, p.upstream)
	return res, false, ""
}

// extractSNI parses a TLS ClientHello payload to find extension 0x0000 (server_name).
func extractSNI(data []byte) (string, error) {
	if len(data) < 4 || data[0] != 0x01 { // 0x01 = ClientHello
		return "", fmt.Errorf("not a ClientHello")
	}

	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) < 4+msgLen {
		return "", fmt.Errorf("truncated ClientHello")
	}

	data = data[4 : 4+msgLen]
	if len(data) < 34 { // 2 bytes version + 32 bytes random
		return "", fmt.Errorf("ClientHello too short")
	}

	// Skip version (2) + random (32)
	pos := 34

	// Skip session ID
	if pos >= len(data) {
		return "", fmt.Errorf("truncated at session ID")
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(data) {
		return "", fmt.Errorf("truncated at cipher suites")
	}
	cipherSuitesLen := int(data[pos])<<8 | int(data[pos+1])
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(data) {
		return "", fmt.Errorf("truncated at compression methods")
	}
	compressionMethodsLen := int(data[pos])
	pos += 1 + compressionMethodsLen

	// Extensions
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

		if extType == 0x0000 { // server_name (SNI)
			sniData := extensions[extPos : extPos+extLen]
			if len(sniData) < 2 {
				return "", fmt.Errorf("truncated SNI data")
			}
			// server_name_list length (2 bytes)
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

				if nameType == 0x00 { // host_name
					return string(listData[listPos : listPos+nameLen]), nil
				}
				listPos += nameLen
			}
		}
		extPos += extLen
	}

	return "", fmt.Errorf("SNI extension not found")
}

// matchDomain matches a domain against an exact name or glob pattern (e.g. *.example.com).
func matchDomain(domain, pattern string) bool {
	if domain == pattern {
		return true
	}
	matched, err := filepath.Match(pattern, domain)
	return err == nil && matched
}

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

type SvcParam struct {
	Key string
	Val string
}

func parseDnsPacket(buf []byte) (id uint16, qName string, qType uint16, err error) {
	if len(buf) < 12 { return 0, "", 0, fmt.Errorf("short") }
	id = binary.BigEndian.Uint16(buf[0:2])
	offset := 12
	var labels []string
	for offset < len(buf) {
		l := int(buf[offset])
		if l == 0 { offset++; break }
		if l&0xC0 == 0xC0 { offset += 2; break }
		offset++; labels = append(labels, string(buf[offset:offset+l]))
		offset += l
	}
	if offset+2 > len(buf) { return 0, "", 0, fmt.Errorf("invalid") }
	qType = binary.BigEndian.Uint16(buf[offset : offset+2])
	return id, strings.Join(labels, "."), qType, nil
}

func createMultiAnsResponse(id uint16, qn string, qt uint16, rds [][]byte, ttl uint32) []byte {
	encodedName := encodeDnsName(qn)
	totalLen := 12 + len(encodedName) + 4
	for _, r := range rds { totalLen += 12 + len(r) }
	buf := make([]byte, totalLen)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x8180)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(rds)))
	offset := 12
	copy(buf[offset:], encodedName)
	offset += len(encodedName)
	binary.BigEndian.PutUint16(buf[offset:], qt)
	offset += 2
	binary.BigEndian.PutUint16(buf[offset:], 1)
	offset += 2
	for _, r := range rds {
		binary.BigEndian.PutUint16(buf[offset:], 0xC00C)
		offset += 2
		binary.BigEndian.PutUint16(buf[offset:], qt)
		offset += 2
		binary.BigEndian.PutUint16(buf[offset:], 1)
		offset += 2
		binary.BigEndian.PutUint32(buf[offset:], ttl)
		offset += 4
		binary.BigEndian.PutUint16(buf[offset:], uint16(len(r)))
		offset += 2
		copy(buf[offset:], r)
		offset += len(r)
	}
	return buf
}

func packHttpsParams(priority uint16, target string, params []SvcParam) []byte {
	var targetBuf []byte
	if target == "." { targetBuf = []byte{0} } else { targetBuf = encodeDnsName(target) }
	var paramBufs [][]byte
	for _, p := range params {
		b := encodeSvcParam(p.Key, p.Val)
		if b != nil { paramBufs = append(paramBufs, b) }
	}
	sort.Slice(paramBufs, func(i, j int) bool {
		return binary.BigEndian.Uint16(paramBufs[i][0:2]) < binary.BigEndian.Uint16(paramBufs[j][0:2])
	})
	totalLen := 2 + len(targetBuf)
	for _, b := range paramBufs { totalLen += len(b) }
	res := make([]byte, totalLen)
	binary.BigEndian.PutUint16(res[0:2], priority)
	copy(res[2:], targetBuf)
	offset := 2 + len(targetBuf)
	for _, b := range paramBufs { copy(res[offset:], b); offset += len(b) }
	return res
}

func encodeSvcParam(key, value string) []byte {
	ids := map[string]uint16{"alpn": 1, "ech": 5}
	id, ok := ids[key]
	if !ok { return nil }
	var valBuf []byte
	if key == "alpn" {
		parts := strings.Split(value, ",")
		for _, p := range parts {
			valBuf = append(valBuf, byte(len(p)))
			valBuf = append(valBuf, []byte(p)...)
		}
	} else {
		dec, _ := base64.StdEncoding.DecodeString(decodeBase64UrlSafeString(value))
		valBuf = dec
	}
	res := make([]byte, 4+len(valBuf))
	binary.BigEndian.PutUint16(res[0:2], id)
	binary.BigEndian.PutUint16(res[2:4], uint16(len(valBuf)))
	copy(res[4:], valBuf)
	return res
}

func encodeDnsName(domain string) []byte {
	parts := strings.Split(domain, ".")
	var buf []byte
	for _, part := range parts {
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0)
	return buf
}

func ipToBytes(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil { return nil }
	if ip4 := ip.To4(); ip4 != nil { return ip4 }
	return ip.To16()
}

func isIpInCompiledCidrs(ipStr string, prefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil { return false }
	for _, p := range prefixes {
		if p.Contains(addr) { return true }
	}
	return false
}

func forwardAndRead(body []byte) ([]byte, error) {
	req, _ := http.NewRequest("POST", UPSTREAM_DNS, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func decodeBase64UrlSafe(s string) []byte {
	dec, _ := base64.StdEncoding.DecodeString(decodeBase64UrlSafeString(s))
	return dec
}

func decodeBase64UrlSafeString(s string) string {
	s = strings.ReplaceAll(s, " ", "+")
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if m := len(s) % 4; m != 0 { s += strings.Repeat("=", 4-m) }
	return s
}
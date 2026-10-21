package assessor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"seclens/internal/report"
)

const (
	resolverDoH    = "doh"
	resolverSystem = "system"
	resolverStub   = "stub"
)

// stubClient speaks DNS over UDP, and TCP when the answer is truncated.
// It does not treat the AD bit as a validation result.
type stubClient struct {
	addr    string
	initErr error
}

func (s *stubClient) reportsAD() bool { return false }

func classifyResolver(spec string) (kind, addr string) {
	s := strings.TrimSpace(spec)
	if strings.EqualFold(s, "system") {
		return resolverSystem, ""
	}
	host, port, err := net.SplitHostPort(s)
	if err == nil && host != "" {
		if _, nerr := strconv.Atoi(port); nerr == nil {
			return resolverStub, s
		}
	}
	return resolverDoH, ""
}

func systemResolverAddr() (string, error) {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("system resolver: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		host := fields[1]
		if _, _, err := net.SplitHostPort(host); err == nil {
			return host, nil
		}
		return net.JoinHostPort(host, "53"), nil
	}
	return "", fmt.Errorf("system resolver: no nameserver in /etc/resolv.conf")
}

func (s *stubClient) LookupTXT(ctx context.Context, name string) ([]string, error) {
	txts, _, err := s.LookupTXTMeta(ctx, name)
	return txts, err
}

func (s *stubClient) LookupTXTMeta(ctx context.Context, name string) ([]string, int, error) {
	return s.lookupTXTFollow(ctx, strings.TrimSuffix(name, "."), 0)
}

func (s *stubClient) lookupTXTFollow(ctx context.Context, name string, depth int) ([]string, int, error) {
	if depth > maxTXTCNAMEDepth {
		return nil, -1, fmt.Errorf("txt cname depth exceeded")
	}
	rcode, answers, err := s.query(ctx, name, 16)
	if err != nil {
		return nil, -1, err
	}
	if rcode == 3 {
		return nil, 3, nil
	}
	var out []string
	var cname string
	for _, a := range answers {
		switch a.typ {
		case 16:
			if a.data != "" {
				out = append(out, a.data)
			}
		case 5:
			if cname == "" {
				cname = a.data
			}
		}
	}
	if len(out) > 0 {
		return out, rcode, nil
	}
	if cname != "" && !strings.EqualFold(cname, name) {
		return s.lookupTXTFollow(ctx, cname, depth+1)
	}
	return nil, rcode, nil
}

func (s *stubClient) LookupMX(ctx context.Context, name string) ([]report.MXRecord, error) {
	rcode, answers, err := s.query(ctx, name, 15)
	if err != nil {
		return nil, err
	}
	var raw []string
	for _, a := range answers {
		if a.typ == 15 {
			raw = append(raw, a.data)
		}
	}
	return mxFromDoH(rcode, raw...)
}

func (s *stubClient) LookupRRWithMeta(ctx context.Context, name string, qtype uint16) (QueryResult, error) {
	rcode, answers, err := s.query(ctx, name, qtype)
	if err != nil {
		return QueryResult{}, err
	}
	if rcode == 3 {
		return QueryResult{Status: rcode, ADUnavailable: true}, nil
	}
	var out []RR
	for _, a := range answers {
		if a.typ != qtype {
			continue
		}
		out = append(out, RR{Name: name, Type: qtype, Data: a.data, TTL: a.ttl})
	}
	return QueryResult{RRs: out, Status: rcode, ADUnavailable: true}, nil
}

func (s *stubClient) LookupRR(ctx context.Context, name string, qtype uint16) ([]RR, error) {
	qr, err := s.LookupRRWithMeta(ctx, name, qtype)
	return qr.RRs, err
}

func (s *stubClient) LookupNS(ctx context.Context, name string) ([]string, error) {
	rcode, answers, err := s.query(ctx, name, 2)
	if err != nil {
		return nil, err
	}
	if rcode == 3 {
		return nil, nil
	}
	var out []string
	for _, a := range answers {
		if a.typ == 2 && a.data != "" {
			out = append(out, strings.TrimSuffix(a.data, "."))
		}
	}
	return out, nil
}

func (s *stubClient) resolveHostIPs(ctx context.Context, host string) ([]net.IP, error) {
	var ips []net.IP
	if _, answers, err := s.query(ctx, host, 1); err == nil {
		for _, a := range answers {
			if a.typ == 1 {
				if ip := net.ParseIP(a.data); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	if _, answers, err := s.query(ctx, host, 28); err == nil {
		for _, a := range answers {
			if a.typ == 28 {
				if ip := net.ParseIP(a.data); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}

type wireRR struct {
	typ  uint16
	ttl  int
	data string
}

func (s *stubClient) query(ctx context.Context, name string, qtype uint16) (int, []wireRR, error) {
	if s.initErr != nil {
		return 0, nil, s.initErr
	}
	if s.addr == "" {
		return 0, nil, fmt.Errorf("stub resolver: empty address")
	}
	msg, err := s.exchange(ctx, buildDNSQuery(name, qtype))
	if err != nil {
		return 0, nil, err
	}
	return parseDNSMessage(msg, qtype)
}

func (s *stubClient) exchange(ctx context.Context, query []byte) ([]byte, error) {
	msg, err := s.exchangeOn(ctx, "udp", query)
	if err != nil {
		return nil, err
	}
	if len(msg) >= 3 && msg[2]&0x02 != 0 {
		return s.exchangeOn(ctx, "tcp", query)
	}
	return msg, nil
}

func (s *stubClient) exchangeOn(ctx context.Context, network string, query []byte) ([]byte, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, network, s.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if network == "tcp" {
		if len(query) > 0xFFFF {
			return nil, fmt.Errorf("stub resolver: query longer than 65535 bytes")
		}
		frame := make([]byte, 2+len(query))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(query))) // #nosec G115 -- length checked against 0xFFFF
		copy(frame[2:], query)
		if _, err := conn.Write(frame); err != nil {
			return nil, err
		}
		var nbuf [2]byte
		if _, err := io.ReadFull(conn, nbuf[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(nbuf[:]))
		if n < 12 || n > 65535 {
			return nil, fmt.Errorf("stub resolver: bad tcp length %d", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		if !sameQueryID(query, buf) {
			return nil, fmt.Errorf("stub resolver: response id mismatch")
		}
		return buf, nil
	}

	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	buf = buf[:n]
	if !sameQueryID(query, buf) {
		return nil, fmt.Errorf("stub resolver: response id mismatch")
	}
	return buf, nil
}

func sameQueryID(query, resp []byte) bool {
	return len(query) >= 2 && len(resp) >= 2 && query[0] == resp[0] && query[1] == resp[1]
}

func buildDNSQuery(name string, qtype uint16) []byte {
	var id [2]byte
	_, _ = rand.Read(id[:])
	qname := encodeDNSName(name)
	hdr := make([]byte, 12)
	copy(hdr[0:2], id[:])
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	binary.BigEndian.PutUint16(hdr[10:12], 1)
	var qtypeBytes [2]byte
	binary.BigEndian.PutUint16(qtypeBytes[:], qtype)
	out := append(hdr, qname...)
	out = append(out, qtypeBytes[0], qtypeBytes[1], 0x00, 0x01)
	out = append(out,
		0,
		0x00, 0x29,
		0x10, 0x00,
		0, 0, 0, 0,
		0, 0,
	)
	return out
}

func labelLen(label string) byte {
	n := len(label)
	if n > 63 {
		n = 63
	}
	return byte(n) // #nosec G115 -- DNS labels are capped at 63 octets above
}

func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}
	}
	var b []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			continue
		}
		b = append(b, labelLen(label))
		b = append(b, label...)
	}
	return append(b, 0)
}

func decodeDNSName(msg []byte, off int) (string, int, error) {
	var labels []string
	jumped := false
	end := off
	for hops := 0; hops < 20; hops++ {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("name out of range")
		}
		n := int(msg[off])
		if n == 0 {
			if !jumped {
				end = off + 1
			}
			return strings.Join(labels, "."), end, nil
		}
		if n&0xC0 == 0xC0 {
			if off+1 >= len(msg) {
				return "", 0, fmt.Errorf("bad compression pointer")
			}
			ptr := int(n&0x3F)<<8 | int(msg[off+1])
			if ptr >= len(msg) {
				return "", 0, fmt.Errorf("compression pointer out of range")
			}
			if !jumped {
				end = off + 2
			}
			off = ptr
			jumped = true
			continue
		}
		if n&0xC0 != 0 {
			return "", 0, fmt.Errorf("unsupported name label")
		}
		off++
		if off+n > len(msg) {
			return "", 0, fmt.Errorf("label out of range")
		}
		labels = append(labels, string(msg[off:off+n]))
		off += n
	}
	return "", 0, fmt.Errorf("name compression loop")
}

func parseDNSMessage(msg []byte, qtype uint16) (int, []wireRR, error) {
	if len(msg) < 12 {
		return 0, nil, fmt.Errorf("short dns message")
	}
	rcode := int(msg[3] & 0x0F)
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := 0; i < qd; i++ {
		_, next, err := decodeDNSName(msg, off)
		if err != nil {
			return 0, nil, err
		}
		if next+4 > len(msg) {
			return 0, nil, fmt.Errorf("short question")
		}
		off = next + 4
	}
	var answers []wireRR
	for i := 0; i < an; i++ {
		_, next, err := decodeDNSName(msg, off)
		if err != nil {
			return 0, nil, err
		}
		if next+10 > len(msg) {
			return 0, nil, fmt.Errorf("short rr")
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := int(binary.BigEndian.Uint32(msg[next+4 : next+8]))
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdataOff := next + 10
		if rdataOff+rdlen > len(msg) {
			return 0, nil, fmt.Errorf("short rdata")
		}
		rdata := msg[rdataOff : rdataOff+rdlen]
		data, err := presentRData(msg, typ, rdata, rdataOff)
		if err != nil {
			return 0, nil, err
		}
		if typ == qtype || typ == 5 {
			answers = append(answers, wireRR{typ: typ, ttl: ttl, data: data})
		}
		off = rdataOff + rdlen
	}
	return rcode, answers, nil
}

func presentRData(msg []byte, typ uint16, rdata []byte, rdataOff int) (string, error) {
	switch typ {
	case 1:
		if len(rdata) != 4 {
			return "", fmt.Errorf("bad A rdata")
		}
		return net.IP(rdata).String(), nil
	case 28:
		if len(rdata) != 16 {
			return "", fmt.Errorf("bad AAAA rdata")
		}
		return net.IP(rdata).String(), nil
	case 2, 5:
		name, _, err := decodeDNSName(msg, rdataOff)
		return name, err
	case 15:
		if len(rdata) < 3 {
			return "", fmt.Errorf("bad MX rdata")
		}
		pref := binary.BigEndian.Uint16(rdata[:2])
		name, _, err := decodeDNSName(msg, rdataOff+2)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s.", pref, name), nil
	case 16:
		var b strings.Builder
		for i := 0; i < len(rdata); {
			n := int(rdata[i])
			i++
			if i+n > len(rdata) {
				return "", fmt.Errorf("bad TXT rdata")
			}
			b.Write(rdata[i : i+n])
			i += n
		}
		return b.String(), nil
	case 43:
		if len(rdata) < 4 {
			return "", fmt.Errorf("bad DS rdata")
		}
		return fmt.Sprintf("%d %d %d %s",
			binary.BigEndian.Uint16(rdata[:2]),
			rdata[2],
			rdata[3],
			strings.ToUpper(hex.EncodeToString(rdata[4:])),
		), nil
	case 48:
		if len(rdata) < 4 {
			return "", fmt.Errorf("bad DNSKEY rdata")
		}
		return fmt.Sprintf("%d %d %d %s",
			binary.BigEndian.Uint16(rdata[:2]),
			rdata[2],
			rdata[3],
			base64.StdEncoding.EncodeToString(rdata[4:]),
		), nil
	case 52:
		if len(rdata) < 3 {
			return "", fmt.Errorf("bad TLSA rdata")
		}
		return fmt.Sprintf("%d %d %d %s", rdata[0], rdata[1], rdata[2], strings.ToUpper(hex.EncodeToString(rdata[3:]))), nil
	default:
		return hex.EncodeToString(rdata), nil
	}
}

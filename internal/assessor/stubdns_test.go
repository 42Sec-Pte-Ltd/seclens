package assessor

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestClassifyResolver(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, kind, addr string
	}{
		{"cloudflare,google", resolverDoH, ""},
		{"system", resolverSystem, ""},
		{"SYSTEM", resolverSystem, ""},
		{"127.0.0.1:53", resolverStub, "127.0.0.1:53"},
		{"[::1]:53", resolverStub, "[::1]:53"},
		{"dns.google", resolverDoH, ""},
	}
	for _, tc := range cases {
		kind, addr := classifyResolver(tc.in)
		if kind != tc.kind || addr != tc.addr {
			t.Errorf("classify(%q)=%s %q want %s %q", tc.in, kind, addr, tc.kind, tc.addr)
		}
	}
}

func TestStubClientMXAndNXDOMAIN(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	go serveStubFixture(t, pc)

	c := &stubClient{addr: pc.LocalAddr().String()}
	if c.reportsAD() {
		t.Fatal("stub resolver must not report AD")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	mxs, err := c.LookupMX(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(mxs) != 1 || mxs[0].Pref != 10 || mxs[0].Host != "mail.example.com" {
		t.Fatalf("mx=%+v", mxs)
	}
	txts, rcode, err := c.LookupTXTMeta(ctx, "example.com")
	if err != nil || rcode != 0 || len(txts) != 1 || txts[0] != "v=spf1 -all" {
		t.Fatalf("txt=%v rcode=%d err=%v", txts, rcode, err)
	}
	_, err = c.LookupMX(ctx, "missing.example")
	if !errors.Is(err, errMXNXDOMAIN) {
		t.Fatalf("nxdomain err=%v", err)
	}
}

func serveStubFixture(t *testing.T, pc net.PacketConn) {
	t.Helper()
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		if len(query) < 12 {
			continue
		}
		name, qend, err := decodeDNSName(query, 12)
		if err != nil || qend+4 > len(query) {
			continue
		}
		qtype := binary.BigEndian.Uint16(query[qend : qend+2])
		var resp []byte
		switch {
		case name == "missing.example":
			resp = dnsResponse(query[:2], query[12:qend+4], 3, nil)
		case qtype == 16:
			resp = dnsResponse(query[:2], query[12:qend+4], 0, []byte(txtAnswer()))
		case qtype == 15:
			resp = dnsResponse(query[:2], query[12:qend+4], 0, []byte(mxAnswer()))
		default:
			resp = dnsResponse(query[:2], query[12:qend+4], 0, nil)
		}
		_, _ = pc.WriteTo(resp, addr)
	}
}

func dnsResponse(id, question []byte, rcode int, answer []byte) []byte {
	hdr := make([]byte, 12)
	copy(hdr[0:2], id)
	hdr[2] = 0x81
	hdr[3] = byte(rcode)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	if len(answer) > 0 {
		binary.BigEndian.PutUint16(hdr[6:8], 1)
	}
	out := append(hdr, question...)
	return append(out, answer...)
}

func mxAnswer() []byte {
	// pointer to the question name at offset 12, type MX, pref 10, mail.example.com
	var b []byte
	b = append(b, 0xC0, 0x0C, 0x00, 0x0F, 0x00, 0x01, 0, 0, 0, 60, 0, 0)
	rdata := append([]byte{0, 10}, encodeDNSName("mail.example.com")...)
	binary.BigEndian.PutUint16(b[len(b)-2:], uint16(len(rdata)))
	return append(b, rdata...)
}

func txtAnswer() []byte {
	txt := []byte("v=spf1 -all")
	rdata := append([]byte{byte(len(txt))}, txt...)
	var b []byte
	b = append(b, 0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01, 0, 0, 0, 60, 0, 0)
	binary.BigEndian.PutUint16(b[len(b)-2:], uint16(len(rdata)))
	return append(b, rdata...)
}

func TestSetDefaultResolverHostPortDoesNotReportAD(t *testing.T) {
	defaultResolverMu.Lock()
	oldClient := DefaultClient
	oldKey := defaultResolverKey
	defaultResolverMu.Unlock()
	t.Cleanup(func() {
		defaultResolverMu.Lock()
		DefaultClient = oldClient
		defaultResolverKey = oldKey
		defaultResolverMu.Unlock()
	})
	SetDefaultResolver("127.0.0.1:9")
	if resolverReportsAD() {
		t.Fatal("host:port resolver reported AD")
	}
	SetDefaultResolver("system")
	if resolverReportsAD() {
		t.Fatal("system resolver reported AD")
	}
}

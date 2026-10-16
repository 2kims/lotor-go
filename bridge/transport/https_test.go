package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

func TestRegistrationEndpointRejectsUnsafeURLs(t *testing.T) {
	for _, endpoint := range []string{
		"http://bridge.example", "https://", "https://user:password@bridge.example", "https://bridge.example?secret=one", "https://bridge.example?", "https://bridge.example#fragment", "https://bridge.example#",
		"https://localhost", "https://localhost.", "https://127.0.0.1", "https://[::1]", "https://169.254.169.254", "https://10.0.0.1", "https://100.100.100.200",
		"https://bridge.example:0", "https://bridge.example:65536", "https://bridge.example:invalid", "https://bridge.example/../admin", "https://bridge.example/%2fadmin", "https://bridge.example//admin", " https://bridge.example",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := ValidateEndpoint(endpoint); err == nil {
				t.Fatal("unsafe registration endpoint accepted")
			}
		})
	}
	for _, endpoint := range []string{"https://bridge.example", "https://bridge.example:8443", "https://bridge.example/customer-functions"} {
		if _, err := ValidateEndpoint(endpoint); err != nil {
			t.Fatalf("valid HTTPS endpoint rejected: %v", err)
		}
	}
}

func runtimeCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "function test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, public, private)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"bridge.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return certificate, roots
}

type unexpectedRoundTripper struct{}

func (unexpectedRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	panic("host application's global transport must not be used")
}

func TestTransportDoesNotDependOnGlobalRoundTripper(t *testing.T) {
	original := http.DefaultTransport
	http.DefaultTransport = unexpectedRoundTripper{}
	defer func() { http.DefaultTransport = original }()
	dispatcher, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.CloseIdleConnections()
	if dispatcher.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy was inherited")
	}
}

// Only the final test socket is mapped to httptest's loopback listener. The
// production DNS/public-IP validation and TLS hostname checks still execute.
func fixtureDispatcher(t *testing.T, server *httptest.Server, configuration *tls.Config) *HTTPSDispatcher {
	t.Helper()
	dispatcher, err := New(Options{TLSConfig: configuration})
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*http.Client{dispatcher.client, dispatcher.mutualTLSClient} {
		transport := client.Transport.(*http.Transport)
		transport.DialContext = publicDialer(&fixedDNS{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}, func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "1.1.1.1:443" {
				t.Fatal("production DNS pinning bypassed")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		})
	}
	t.Cleanup(dispatcher.CloseIdleConnections)
	return dispatcher
}

func TestHTTPSDispatcherProtocolLimitsRedirectsAndConnectionReuse(t *testing.T) {
	certificate, roots := runtimeCertificate(t)
	var requests atomic.Int32
	var connections atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.ProtoMajor != 2 {
			t.Error("HTTP/2 was not negotiated")
		}
		if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || r.URL.Path != "/customer/v1/functions/challenge" {
			t.Error("unexpected function route")
		}
		w.Header().Set("Content-Type", "application/json")
		var message bridge.SignedMessage
		if json.NewDecoder(r.Body).Decode(&message) != nil {
			t.Error("invalid request")
		}
		switch message.KeyID {
		case "redirect":
			http.Redirect(w, r, "https://other.example/v1/functions/invoke", 307)
		case "oversized":
			_, _ = w.Write([]byte(strings.Repeat("x", bridge.MaximumBodyBytes+1)))
		case "trailing":
			_, _ = io.WriteString(w, `{"key_id":"key","payload":"payload","signature":"signature"} {}`)
		case "encoding":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = io.WriteString(w, `{}`)
		default:
			_ = json.NewEncoder(w).Encode(bridge.SignedMessage{KeyID: "key", Payload: "payload", Signature: "signature"})
		}
	}))
	server.EnableHTTP2 = true
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	dispatcher := fixtureDispatcher(t, server, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
	for index, test := range []struct {
		key   string
		valid bool
	}{{"valid", true}, {"valid", true}, {"redirect", false}, {"oversized", false}, {"trailing", false}, {"encoding", false}} {
		_, err := dispatcher.Send(t.Context(), "https://bridge.example/customer", "challenge", bridge.SignedMessage{KeyID: test.key, Payload: "request", Signature: "signature"})
		if (err == nil) != test.valid {
			t.Fatalf("%s result: %v", test.key, err)
		}
		if index == 1 && connections.Load() != 1 {
			t.Fatal("successful invocations did not reuse their TLS connection")
		}
	}
	if requests.Load() != 6 {
		t.Fatal("redirect followed or request skipped")
	}
	transport := dispatcher.client.Transport.(*http.Transport)
	if transport.Proxy != nil || !transport.ForceAttemptHTTP2 || transport.TLSHandshakeTimeout == 0 || dispatcher.client.Timeout == 0 {
		t.Fatal("unsafe default transport")
	}
}

func TestHTTPSDispatcherEnforcesServerAndMutualTLS(t *testing.T) {
	certificate, roots := runtimeCertificate(t)
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.ProtoMajor != 1 {
			t.Error("HTTP/1.1 fallback was not used")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bridge.SignedMessage{KeyID: "key", Payload: "payload", Signature: "signature"})
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}
	server.StartTLS()
	defer server.Close()
	otherCertificate, _ := runtimeCertificate(t)
	for _, test := range []struct {
		configuration *tls.Config
		name          string
		valid         bool
	}{
		{name: "trusted mTLS", configuration: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, valid: true},
		{name: "missing client certificate", configuration: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, valid: false},
		{name: "untrusted client certificate", configuration: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{otherCertificate}, MinVersion: tls.VersionTLS12}, valid: false},
		{name: "untrusted server", configuration: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dispatcher := fixtureDispatcher(t, server, test.configuration)
			_, err := dispatcher.SendMutualTLS(t.Context(), "https://bridge.example", "challenge", bridge.SignedMessage{KeyID: "key"})
			if (err == nil) != test.valid {
				t.Fatalf("unexpected TLS result: %v", err)
			}
		})
	}
	if calls.Load() != 1 {
		t.Fatal("untrusted TLS peer reached function handler")
	}
	for _, configuration := range []*tls.Config{{InsecureSkipVerify: true}, {ServerName: "other.example"}, {MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12}} {
		if _, err := New(Options{TLSConfig: configuration}); err == nil {
			t.Fatal("unsafe TLS override accepted")
		}
	}
}

func TestDNSRebindingIsRevalidatedOnEachConnection(t *testing.T) {
	resolver := &fixedDNS{addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	calls := 0
	dial := publicDialer(resolver, func(context.Context, string, string) (net.Conn, error) {
		calls++
		left, right := net.Pipe()
		_ = right.Close()
		return left, nil
	})
	connection, err := dial(t.Context(), "tcp", "bridge.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	resolver.addresses = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if _, err = dial(t.Context(), "tcp", "bridge.example:443"); err == nil || calls != 1 {
		t.Fatal("rebound DNS reached private destination")
	}
}

func TestPublicDestinationClassification(t *testing.T) {
	for _, address := range []string{"::7f00:1", "2001::7f00:1", "fec0::1"} {
		if publicAddress(netip.MustParseAddr(address)) {
			t.Fatalf("reserved IPv6 destination accepted: %s", address)
		}
	}
	for _, address := range []string{"0.0.0.0", "0.1.2.3", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.0.1", "192.0.0.1", "192.0.2.1", "192.168.0.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "::", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "ff00::1", "2001:db8::1", "2002:7f00:1::1", "64:ff9b::7f00:1"} {
		if publicAddress(netip.MustParseAddr(address)) {
			t.Fatalf("non-public destination accepted: %s", address)
		}
	}
	for _, address := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(address)) {
			t.Fatalf("public destination rejected: %s", address)
		}
	}
}

type fixedDNS struct {
	addresses []netip.Addr
	calls     int
}

func (resolver *fixedDNS) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	resolver.calls++
	return resolver.addresses, nil
}

func TestDNSValidationPinsConnectionAndRejectsMixedAnswers(t *testing.T) {
	for _, test := range []struct {
		name      string
		addresses []netip.Addr
		allowed   bool
	}{
		{"public", []netip.Addr{netip.MustParseAddr("1.1.1.1")}, true},
		{"private", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, false},
		{"mixed", []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("169.254.169.254")}, false},
		{"empty", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolver := &fixedDNS{addresses: test.addresses}
			called := false
			dial := publicDialer(resolver, func(_ context.Context, network, address string) (net.Conn, error) {
				called = true
				if network != "tcp" || address != "1.1.1.1:443" {
					t.Fatalf("DNS was not pinned: %s %s", network, address)
				}
				left, right := net.Pipe()
				_ = right.Close()
				return left, nil
			})
			connection, err := dial(t.Context(), "tcp", "bridge.example:443")
			if connection != nil {
				_ = connection.Close()
			}
			if called != test.allowed || (err == nil) != test.allowed || resolver.calls != 1 {
				t.Fatalf("unexpected dial result: called=%t err=%v", called, err)
			}
		})
	}
}

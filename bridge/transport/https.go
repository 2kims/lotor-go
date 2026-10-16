// Package transport implements safe direct HTTPS dispatch for registered functions.
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/2kims/lotor-go/bridge"
)

// HTTPSDispatcher carries signed protocol messages only. It makes no resource
// authorization decisions and never follows redirects or uses environment proxies.
type HTTPSDispatcher struct {
	client          *http.Client
	mutualTLSClient *http.Client
	mutualTLS       bool
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

// Options configures trusted deployment networking. DialContext receives only
// literal public IPs already validated by the transport; custom implementations
// must preserve that destination. Neither option is accepted from HTTP input.
type Options struct {
	TLSConfig   *tls.Config
	Resolver    Resolver
	DialContext func(context.Context, string, string) (net.Conn, error)
}

func New(options Options) (*HTTPSDispatcher, error) {
	configuration := options.TLSConfig
	tlsConfiguration := &tls.Config{MinVersion: tls.VersionTLS12}
	if configuration != nil {
		tlsConfiguration = configuration.Clone()
		if tlsConfiguration.InsecureSkipVerify || tlsConfiguration.ServerName != "" {
			return nil, bridge.ErrInvalid
		}
		if tlsConfiguration.MinVersion < tls.VersionTLS12 {
			tlsConfiguration.MinVersion = tls.VersionTLS12
		}
		if tlsConfiguration.MaxVersion != 0 && tlsConfiguration.MaxVersion < tlsConfiguration.MinVersion {
			return nil, bridge.ErrInvalid
		}
	}
	// Do not inherit a process-global RoundTripper, proxy, custom TLS dialer or
	// insecure TLS policy installed by the host application's instrumentation.
	transport := &http.Transport{IdleConnTimeout: 90 * time.Second, ExpectContinueTimeout: time.Second}
	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := options.DialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	transport.DialContext = publicDialer(resolver, dial)
	transport.TLSClientConfig = tlsConfiguration
	transport.ForceAttemptHTTP2 = true
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.MaxResponseHeaderBytes = 32 << 10
	transport.DisableCompression = true
	transport.MaxConnsPerHost = 16
	transport.MaxIdleConnsPerHost = 4
	transport.MaxIdleConns = 64
	newClient := func(transport *http.Transport) *http.Client {
		return &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	strict := transport.Clone()
	strict.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return requiredMTLSDial(ctx, strict, network, address)
	}
	return &HTTPSDispatcher{client: newClient(transport), mutualTLSClient: newClient(strict), mutualTLS: len(tlsConfiguration.Certificates) > 0 || tlsConfiguration.GetClientCertificate != nil}, nil
}

func (dispatcher *HTTPSDispatcher) MutualTLSConfigured() bool { return dispatcher.mutualTLS }

func (dispatcher *HTTPSDispatcher) CloseIdleConnections() {
	dispatcher.client.CloseIdleConnections()
	dispatcher.mutualTLSClient.CloseIdleConnections()
}

func requiredMTLSDial(ctx context.Context, transport *http.Transport, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	connection, err := transport.DialContext(ctx, network, address)
	if err != nil {
		return nil, bridge.ErrUnavailable
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		_ = connection.Close()
		return nil, bridge.ErrUnavailable
	}
	configuration := transport.TLSClientConfig.Clone()
	configuration.ServerName = host
	// A resumed session does not necessarily repeat client-certificate exchange.
	// Connection pooling is retained; new connections prove client presentation.
	configuration.ClientSessionCache = nil
	original := configuration.GetClientCertificate
	presented := false
	configuration.GetClientCertificate = func(request *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		var certificate *tls.Certificate
		if original != nil {
			certificate, err = original(request)
		} else {
			for index := range configuration.Certificates {
				if request.SupportsCertificate(&configuration.Certificates[index]) == nil {
					certificate = &configuration.Certificates[index]
					break
				}
			}
		}
		if err != nil {
			return nil, err
		}
		if certificate == nil {
			return &tls.Certificate{}, nil
		}
		presented = len(certificate.Certificate) > 0
		return certificate, nil
	}
	secure := tls.Client(connection, configuration)
	if err = secure.HandshakeContext(ctx); err != nil || !presented {
		_ = secure.Close()
		return nil, bridge.ErrUnavailable
	}
	return secure, nil
}

func (dispatcher *HTTPSDispatcher) SendMutualTLS(ctx context.Context, endpoint, operation string, message bridge.SignedMessage) (bridge.SignedMessage, error) {
	if !dispatcher.mutualTLS {
		return bridge.SignedMessage{}, bridge.ErrUnavailable
	}
	return dispatcher.send(ctx, dispatcher.mutualTLSClient, endpoint, operation, message)
}

// Send permits only the two fixed protocol operations. Signature/result and
// one-use challenge validation belong to the calling lifecycle service.
// A transport error does not establish that invocation effects did not occur;
// callers must preserve the invocation identity rather than blindly rerun it.
func (dispatcher *HTTPSDispatcher) Send(ctx context.Context, endpoint, operation string, message bridge.SignedMessage) (bridge.SignedMessage, error) {
	return dispatcher.send(ctx, dispatcher.client, endpoint, operation, message)
}

func (dispatcher *HTTPSDispatcher) send(ctx context.Context, client *http.Client, endpoint, operation string, message bridge.SignedMessage) (bridge.SignedMessage, error) {
	parsed, err := ValidateEndpoint(endpoint)
	if err != nil {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	if operation != "challenge" && operation != "invoke" {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	body, err := json.Marshal(message)
	if err != nil || len(body) > bridge.MaximumBodyBytes {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/v1/functions/" + operation
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(body))
	if err != nil {
		return bridge.SignedMessage{}, bridge.ErrInvalid
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return bridge.SignedMessage{}, bridge.ErrUnavailable
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || response.StatusCode != http.StatusOK || response.Header.Get("Content-Encoding") != "" {
		return bridge.SignedMessage{}, bridge.ErrUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, bridge.MaximumBodyBytes+1))
	if err != nil || len(raw) > bridge.MaximumBodyBytes {
		return bridge.SignedMessage{}, bridge.ErrUnavailable
	}
	var result bridge.SignedMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || result.KeyID == "" || result.Payload == "" || result.Signature == "" {
		return bridge.SignedMessage{}, bridge.ErrUnavailable
	}
	return result, nil
}

var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("64:ff9b::/96"), netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("::/96"), netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("fec0::/10"),
}

// ValidateEndpoint validates syntax and literal destinations at registration.
// DNS names are revalidated and pinned by publicDialer on every new connection.
func ValidateEndpoint(endpoint string) (*url.URL, error) {
	if endpoint != strings.TrimSpace(endpoint) || len(endpoint) > 2048 || strings.Contains(endpoint, "#") {
		return nil, bridge.ErrInvalid
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" || parsed.RawPath != "" {
		return nil, bridge.ErrInvalid
	}
	if strings.Contains(parsed.Path, "\\") || strings.Contains(parsed.Path, "//") {
		return nil, bridge.ErrInvalid
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, bridge.ErrInvalid
		}
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.Contains(host, "%") {
		return nil, bridge.ErrInvalid
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return nil, bridge.ErrInvalid
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return nil, bridge.ErrInvalid
		}
	}
	if address, err := netip.ParseAddr(host); err == nil && !publicAddress(address) {
		return nil, bridge.ErrInvalid
	}
	return parsed, nil
}

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

type dialContext func(context.Context, string, string) (net.Conn, error)

func publicDialer(resolver Resolver, dial dialContext) dialContext {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, bridge.ErrUnavailable
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, bridge.ErrUnavailable
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var addresses []netip.Addr
		if literal, err := netip.ParseAddr(host); err == nil {
			addresses = []netip.Addr{literal}
		} else {
			addresses, err = resolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, bridge.ErrUnavailable
			}
		}
		if len(addresses) < 1 || len(addresses) > 16 {
			return nil, bridge.ErrUnavailable
		}
		for _, ip := range addresses {
			if !publicAddress(ip) {
				return nil, bridge.ErrUnavailable
			}
		}
		for _, ip := range addresses {
			connection, err := dial(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
			if err == nil {
				return connection, nil
			}
		}
		return nil, bridge.ErrUnavailable
	}
}

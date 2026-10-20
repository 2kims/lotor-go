package development

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/2kims/lotor-go/bridge"
	"github.com/2kims/lotor-go/bridge/transport"
	"github.com/coder/websocket"
)

type SessionProvider func(context.Context) (Session, error)

type ConnectorOptions struct {
	Handler       http.Handler
	Session       SessionProvider
	HTTPClient    *http.Client
	Ready         chan<- struct{}
	MaxConcurrent int
	ReconnectMin  time.Duration
	ReconnectMax  time.Duration
}

type Connector struct {
	client  *http.Client
	slots   chan struct{}
	options ConnectorOptions
}

func NewConnector(options ConnectorOptions) (*Connector, error) {
	if options.Session == nil || options.Handler == nil {
		return nil, bridge.ErrInvalid
	}
	if options.MaxConcurrent == 0 {
		options.MaxConcurrent = 4
	}
	if options.ReconnectMin == 0 {
		options.ReconnectMin = 250 * time.Millisecond
	}
	if options.ReconnectMax == 0 {
		options.ReconnectMax = 30 * time.Second
	}
	if options.MaxConcurrent < 1 || options.MaxConcurrent > 64 || options.ReconnectMin <= 0 || options.ReconnectMax < options.ReconnectMin || options.ReconnectMax > time.Minute {
		return nil, bridge.ErrInvalid
	}
	client := http.DefaultClient
	if options.HTTPClient != nil {
		client = options.HTTPClient
	}
	isolated := *client
	isolated.Jar = nil
	isolated.Timeout = 0 // The handshake has its own deadline; the socket is long-lived.
	isolated.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Connector{options: options, client: &isolated, slots: make(chan struct{}, options.MaxConcurrent)}, nil
}

// Run reconnects transport with fresh admission. It never saves or resends a
// request frame. The supplied bridge handler owns durable execution idempotency.
func (connector *Connector) Run(ctx context.Context) error {
	delay := connector.options.ReconnectMin
	for {
		started := time.Now()
		err := connector.Connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, bridge.ErrInvalid) || errors.Is(err, bridge.ErrUnauthorized) {
			return err
		}
		if time.Since(started) > 10*time.Second {
			delay = connector.options.ReconnectMin
		}
		jitter, entropyErr := rand.Int(rand.Reader, big.NewInt(max(1, int64(delay/2))))
		if entropyErr != nil {
			return bridge.ErrUnavailable
		}
		wait := time.NewTimer(max(time.Nanosecond, delay/2+time.Duration(jitter.Int64())))
		select {
		case <-ctx.Done():
			wait.Stop()
			return ctx.Err()
		case <-wait.C:
		}
		if delay < connector.options.ReconnectMax/2 {
			delay *= 2
		} else {
			delay = connector.options.ReconnectMax
		}
	}
}

// Connect runs one authenticated transport generation. All unfinished handlers
// are canceled when it ends, without any permission to execute them again.
func (connector *Connector) Connect(ctx context.Context) error {
	session, err := connector.options.Session(ctx)
	if err != nil {
		return err
	}
	if !validSession(session) {
		return bridge.ErrInvalid
	}
	connect, stop := context.WithTimeout(ctx, 10*time.Second)
	conn, response, err := websocket.Dial(connect, session.ConnectorURL, &websocket.DialOptions{HTTPClient: connector.client, HTTPHeader: http.Header{"Authorization": []string{"Bearer " + session.Credential}}, Subprotocols: []string{Subprotocol}, CompressionMode: websocket.CompressionDisabled})
	stop()
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if response != nil && (response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden) {
			return bridge.ErrUnauthorized
		}
		return bridge.ErrUnavailable
	}
	defer func() { _ = conn.CloseNow() }()
	if conn.Subprotocol() != Subprotocol {
		return bridge.ErrInvalid
	}
	conn.SetReadLimit(MaxFrameBytes)
	ready, cancelReady := context.WithTimeout(ctx, 10*time.Second)
	kind, raw, err := conn.Read(ready)
	cancelReady()
	if err != nil || kind != websocket.MessageText {
		return bridge.ErrUnavailable
	}
	frame, err := DecodeFrame(raw)
	if err != nil || frame.Kind != "ready" {
		return bridge.ErrInvalid
	}
	if connector.options.Ready != nil {
		select {
		case connector.options.Ready <- struct{}{}:
		default:
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var activeMu sync.Mutex
	active := map[string]context.CancelFunc{}
	defer func() {
		activeMu.Lock()
		defer activeMu.Unlock()
		for _, cancel := range active {
			cancel()
		}
	}()
	write := func(frame Frame) error {
		raw, err := json.Marshal(frame)
		if err != nil {
			return bridge.ErrInvalid
		}
		writeContext, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		return conn.Write(writeContext, websocket.MessageText, raw)
	}
	go func() {
		defer cancel()
		defer func() { _ = conn.CloseNow() }()
		nextRefresh := sessionRefreshAt(session, time.Now())
		timer := time.NewTimer(min(15*time.Second, time.Until(nextRefresh)))
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			// Never let a heartbeat or renewal outlive the current lease.
			lease, stopLease := context.WithDeadline(ctx, time.UnixMicro(session.ExpiresAt))
			ping, stop := context.WithTimeout(lease, 5*time.Second)
			err := conn.Ping(ping)
			stop()
			if err != nil {
				stopLease()
				return
			}
			if time.Now().Before(nextRefresh) {
				stopLease()
				timer.Reset(min(15*time.Second, time.Until(nextRefresh)))
				continue
			}
			refresh, stop := context.WithTimeout(lease, 10*time.Second)
			next, err := connector.options.Session(refresh)
			stop()
			stopLease()
			if err != nil {
				if time.Now().Add(15*time.Second).UnixMicro() >= session.ExpiresAt || errors.Is(err, bridge.ErrInvalid) || errors.Is(err, bridge.ErrUnauthorized) {
					return
				}
				nextRefresh = time.Now().Add(15 * time.Second)
				timer.Reset(time.Until(nextRefresh))
				continue
			}
			if !validSession(next) || next.ConnectionID != session.ConnectionID || next.ConnectorURL != session.ConnectorURL {
				return
			}
			if write(Frame{Version: 1, Kind: "authenticate", Credential: next.Credential}) != nil {
				return
			}
			session = next
			nextRefresh = sessionRefreshAt(session, time.Now())
			timer.Reset(min(15*time.Second, time.Until(nextRefresh)))
		}
	}()
	for {
		kind, raw, err := conn.Read(ctx)
		if err != nil {
			return bridge.ErrUnavailable
		}
		if kind != websocket.MessageText {
			return bridge.ErrInvalid
		}
		frame, err := DecodeFrame(raw)
		if err != nil {
			return err
		}
		activeMu.Lock()
		switch frame.Kind {
		case "cancel":
			if stop := active[frame.ID]; stop != nil {
				stop()
			}
			activeMu.Unlock()
		case "request":
			if active[frame.ID] != nil || frame.Deadline <= time.Now().UnixMicro() || frame.Deadline > time.Now().Add(time.Minute).UnixMicro() {
				activeMu.Unlock()
				return bridge.ErrInvalid
			}
			select {
			case connector.slots <- struct{}{}:
			default:
				activeMu.Unlock()
				return bridge.ErrUnavailable
			}
			requestContext, stop := context.WithDeadline(ctx, time.UnixMicro(frame.Deadline))
			active[frame.ID] = stop
			activeMu.Unlock()
			go func(frame Frame) {
				defer func() { <-connector.slots; activeMu.Lock(); delete(active, frame.ID); activeMu.Unlock(); stop() }()
				response := connector.handle(requestContext, frame)
				if write(response) != nil {
					cancel()
					_ = conn.CloseNow()
				}
			}(frame)
		default:
			activeMu.Unlock()
			return bridge.ErrInvalid
		}
	}
}

// Renew halfway through a short remaining lease, and at least once a minute
// for ordinary five-minute sessions. Reused near-expiry sessions need renewal
// sooner than the heartbeat interval, without changing the server's TTL.
func sessionRefreshAt(session Session, now time.Time) time.Time {
	return now.Add(min(time.Minute, time.UnixMicro(session.ExpiresAt).Sub(now)/2))
}

func validSession(session Session) bool {
	if !connectionIdentifier(session.ConnectionID) || session.Credential == "" || len(session.Credential) > 8192 || strings.ContainsAny(session.Credential, " \r\n\t") || !strings.HasPrefix(session.ConnectorURL, "wss://") || session.ExpiresAt <= time.Now().UnixMicro() || session.ExpiresAt > time.Now().Add(5*time.Minute).UnixMicro() {
		return false
	}
	parsed, err := transport.ValidateEndpoint("https://" + strings.TrimPrefix(session.ConnectorURL, "wss://"))
	return err == nil && session.ConnectionID != "" && parsed.Path == "/v1/development-connections/"+session.ConnectionID+"/connect"
}

type boundedResponse struct {
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (response *boundedResponse) Header() http.Header { return response.header }
func (response *boundedResponse) WriteHeader(status int) {
	if response.status == 0 {
		response.status = status
	}
}

func (response *boundedResponse) Write(body []byte) (int, error) {
	if response.status == 0 {
		response.status = 200
	}
	if len(body) > MaxBodyBytes-response.body.Len() {
		response.overflow = true
		return 0, bridge.ErrInvalid
	}
	return response.body.Write(body)
}

func (connector *Connector) handle(ctx context.Context, frame Frame) (result Frame) {
	result = Frame{Version: 1, Kind: "response", ID: frame.ID, Status: 502, Body: json.RawMessage(`{"code":"development_handler_unavailable"}`)}
	defer func() {
		if recover() != nil {
			result = Frame{Version: 1, Kind: "response", ID: frame.ID, Status: 502, Body: json.RawMessage(`{"code":"development_handler_unavailable"}`)}
		}
	}()
	request, err := http.NewRequestWithContext(ctx, "POST", "http://local-bridge/v1/functions/"+frame.Operation, bytes.NewReader(frame.Body))
	if err != nil {
		return result
	}
	request.Header.Set("Content-Type", "application/json")
	response := &boundedResponse{header: make(http.Header)}
	connector.options.Handler.ServeHTTP(response, request)
	if response.status == 0 {
		response.status = 200
	}
	if response.overflow || response.status < 200 || response.status > 599 || !json.Valid(response.body.Bytes()) {
		return result
	}
	result.Status, result.Body = response.status, append([]byte(nil), response.body.Bytes()...)
	return result
}

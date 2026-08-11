package lotor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// LWPError is a structured protocol error. Callers can inspect Code without parsing error text.
type LWPError struct {
	Message string
	Code    uint16
}

const (
	// ErrorCodeIdempotencyConflict means one idempotency key was reused with different command input.
	ErrorCodeIdempotencyConflict uint16 = 0x0013
)

func (e *LWPError) Error() string {
	return fmt.Sprintf("lwp error %d: %s", e.Code, e.Message)
}

// IsLWPError reports whether err is a protocol error with the requested code.
func IsLWPError(err error, code uint16) bool {
	var target *LWPError
	return errors.As(err, &target) && target.Code == code
}

// Client is one pipelined LWP connection to lotord: request_id correlation (a reader goroutine fans
// RESP frames to per-request channels) plus WATCH subscriptions (EVENT frames routed to handlers by
// watch id).
type Client struct {
	conn   net.Conn
	pend   map[uint32]chan frame
	subs   map[string]func(Event) // watch_id -> handler
	closed chan struct{}
	mu     sync.Mutex
	nextID uint32
}

// Event is a server-pushed WATCH event (e.g. wallet_low, grant_changed).
type Event struct {
	Detail  map[string]int64 // numeric detail (e.g. {"balance":15,"threshold":20})
	Type    string           // "wallet_low" | "grant_changed" | ...
	Target  string           // addr the event is about (e.g. "org:acme/credits")
	WatchID string
	LogSeq  uint64
}

// Dial connects and completes the HELLO handshake.
func Dial(ctx context.Context, addr string) (*Client, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return newClient(conn)
}

// DialTLS connects with TLS and completes the HELLO handshake.
func DialTLS(ctx context.Context, addr string, config *tls.Config) (*Client, error) {
	if config == nil {
		return nil, errors.New("TLS config is required")
	}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: config.Clone()}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return newClient(conn)
}

func newClient(conn net.Conn) (*Client, error) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	c := &Client{conn: conn, pend: map[uint32]chan frame{}, subs: map[string]func(Event){}, closed: make(chan struct{})}
	go c.readLoop()
	if _, err := c.do(opHELLO, []value{vU64(protoVersion), vU64(0), vStr("lotor-go")}); err != nil {
		c.Close()
		return nil, fmt.Errorf("hello: %w", err)
	}
	return c, nil
}

func (c *Client) readLoop() {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := c.conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			for {
				f, consumed, ok := decodeFrame(buf)
				if !ok {
					break
				}
				buf = buf[consumed:]
				if f.typ == frameRESP {
					c.mu.Lock()
					ch := c.pend[f.reqID]
					delete(c.pend, f.reqID)
					c.mu.Unlock()
					if ch != nil {
						ch <- f
					}
				} else if f.typ == frameEVENT {
					c.dispatchEvent(f)
				}
				// PONG ignored by this client.
			}
		}
		if err != nil {
			close(c.closed)
			c.mu.Lock()
			for id, ch := range c.pend {
				close(ch)
				delete(c.pend, id)
			}
			c.mu.Unlock()
			return
		}
	}
}

// do sends a REQ and returns the response args (or an error on ERR / disconnect).
func (c *Client) do(opcode uint16, args []value) ([]value, error) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan frame, 1)
	c.pend[id] = ch
	c.mu.Unlock()

	if _, err := c.conn.Write(encodeFrame(frame{typ: frameREQ, reqID: id, opcode: opcode, args: args})); err != nil {
		c.mu.Lock()
		delete(c.pend, id)
		c.mu.Unlock()
		return nil, err
	}
	select {
	case f, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("connection closed")
		}
		if f.opcode == statusERR {
			code := f.args[0].asNum()
			msg := ""
			if len(f.args) > 1 {
				msg = f.args[1].asStr()
			}
			if code < 0 || code > int64(^uint16(0)) {
				return nil, fmt.Errorf("invalid lwp error code")
			}
			return nil, &LWPError{Code: uint16(code), Message: msg}
		}
		return f.args, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("request timeout")
	}
}

// Auth binds the connection to a tenant.
func (c *Client) Auth(apiKey string) error {
	_, err := c.do(opAUTH, []value{vStr(apiKey)})
	return err
}

// Verified is an AUTH.VERIFY result.
type Verified struct {
	Subject string
	Org     string
	Reason  string
	Valid   bool
}

// AuthVerify validates an end-user credential (1=JWT, 2=cookie).
func (c *Client) AuthVerify(credType int, credential string) (Verified, error) {
	if credType < 0 {
		return Verified{}, fmt.Errorf("credential type must be non-negative")
	}
	a, err := c.do(opAUTHVERIFY, []value{vU64(uint64(credType)), vStr(credential)})
	if err != nil {
		return Verified{}, err
	}
	v := Verified{}
	if len(a) >= 6 {
		v.Valid = a[0].asBool()
		v.Subject = a[1].asStr()
		v.Org = a[2].asStr()
		v.Reason = a[5].asStr()
	}
	return v, nil
}

// Decision is an ACCESS.CHECK result.
type Decision struct {
	Reason             string
	Evidence           string
	CompositionVersion uint64
	Allow              bool
}

// PolicyInput contains only declarative decision facts; PolicyCheck performs no external effect.
type PolicyInput struct {
	Pin                CompositionPin
	ScopeRef           string
	DestinationRef     string
	RegionRef          string
	ExecutionPolicyRef string
	EvidenceRefs       []string
	RetentionDays      uint64
	Reveal             bool
	Export             bool
}

// PolicyDecision returns deterministic exact-pin evidence.
type PolicyDecision struct {
	State              string
	Reasons            []string
	Evidence           string
	SourcePins         []string
	CompositionVersion uint64
}

// PolicyCheck evaluates approval, data-protection, security, and residency policy locally.
func (c *Client) PolicyCheck(subject string, input PolicyInput) (PolicyDecision, error) {
	args, err := c.do(opPOLICYCHECK, []value{
		vAddr(subject),
		vStr(input.Pin.Operation),
		policyContext(subject, input),
	})
	if err != nil {
		return PolicyDecision{}, err
	}
	result := PolicyDecision{}
	if len(args) >= 5 {
		result.State = args[0].asStr()
		for _, value := range args[1].List {
			result.Reasons = append(result.Reasons, value.asStr())
		}
		result.Evidence = args[2].asStr()
		result.CompositionVersion = args[3].U64
		for _, value := range args[4].List {
			result.SourcePins = append(result.SourcePins, value.asStr())
		}
	}
	return result, nil
}

func policyContext(subject string, input PolicyInput) value {
	evidence := append([]string(nil), input.EvidenceRefs...)
	sort.Strings(evidence)
	evidenceValues := make([]value, 0, len(evidence))
	for _, ref := range evidence {
		evidenceValues = append(evidenceValues, vStr(ref))
	}
	compositionSubject := input.Pin.CompositionSubject
	if compositionSubject == "" {
		compositionSubject = subject
	}
	return vMap(map[string]value{
		"composition_hash":     vStr(input.Pin.ResultHash),
		"composition_version":  vU64(input.Pin.Version),
		"composition_subject":  vAddr(compositionSubject),
		"scope_ref":            vStr(input.ScopeRef),
		"destination_ref":      vStr(input.DestinationRef),
		"region_ref":           vStr(input.RegionRef),
		"execution_policy_ref": vStr(input.ExecutionPolicyRef),
		"evidence_refs":        vList(evidenceValues),
		"retention_days":       vU64(input.RetentionDays),
		"reveal":               vBool(input.Reveal),
		"export":               vBool(input.Export),
	})
}

// AccessCheck resolves (subject, relation, object).
func (c *Client) AccessCheck(subject, relation, object string) (Decision, error) {
	a, err := c.do(opACCESSCHECK, []value{vAddr(subject), vStr(relation), vAddr(object)})
	if err != nil {
		return Decision{}, err
	}
	d := Decision{}
	if len(a) >= 2 {
		d.Allow = a[0].asNum() == 1
		d.Reason = a[1].asStr()
	}
	return d, nil
}

// AccessGrant adds a durable relationship tuple. ExpiresAt is an epoch timestamp in
// microseconds; zero keeps the tuple until it is explicitly revoked.
func (c *Client) AccessGrant(subject, relation, object string, expiresAt uint64) error {
	values, err := c.do(opACCESSGRANT, []value{vAddr(subject), vStr(relation), vAddr(object), vU64(expiresAt)})
	if err != nil {
		return err
	}
	if len(values) == 0 || !values[0].asBool() {
		return errors.New("access grant was not committed")
	}
	return nil
}

// AccessRevoke removes a durable relationship tuple.
func (c *Client) AccessRevoke(subject, relation, object string) error {
	values, err := c.do(opACCESSREVOKE, []value{vAddr(subject), vStr(relation), vAddr(object)})
	if err != nil {
		return err
	}
	if len(values) == 0 || !values[0].asBool() {
		return errors.New("access revoke was not committed")
	}
	return nil
}

// AccessExpand lists subjects that hold relation to object. A zero limit asks
// the runtime for its default bounded result set.
func (c *Client) AccessExpand(object, relation string, limit uint64) ([]string, error) {
	values, err := c.do(opACCESSEXPAND, []value{vAddr(object), vStr(relation), vU64(limit)})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 || values[0].Kind != tagList {
		return []string{}, nil
	}
	result := make([]string, 0, len(values[0].List))
	for _, value := range values[0].List {
		if item := value.asStr(); item != "" {
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result, nil
}

// AccessCheckPinned resolves a canonical entitlement or authorization decision against one exact
// immutable runtime composition. Set pin.CompositionSubject when the checked identity differs from
// the Deal/composition subject.
func (c *Client) AccessCheckPinned(
	subject, relation, object string,
	pin CompositionPin,
) (Decision, error) {
	a, err := c.do(opACCESSCHECK, []value{
		vAddr(subject), vStr(relation), vAddr(object), accessPin(pin),
	})
	if err != nil {
		return Decision{}, err
	}
	result := Decision{}
	if len(a) >= 2 {
		result.Allow = a[0].asNum() == 1
		result.Reason = a[1].asStr()
	}
	if len(a) >= 5 {
		result.Evidence = a[3].asStr()
		result.CompositionVersion = a[4].U64
	}
	return result, nil
}

func accessPin(pin CompositionPin) value {
	values := map[string]value{
		"operation":           vStr(pin.Operation),
		"composition_hash":    vStr(pin.ResultHash),
		"composition_version": vU64(pin.Version),
	}
	if pin.CompositionSubject != "" {
		values["composition_subject"] = vAddr(pin.CompositionSubject)
	}
	return vMap(values)
}

// ConfBlob is a versioned configuration projection returned by lotord. Payload is opaque to the
// transport; callers must validate its content type and application contract before decoding it.
type ConfBlob struct {
	Board       string
	Etag        string
	ContentType string
	Payload     []byte
	Version     uint64
	Changed     bool
}

// ConfGet reads one configuration projection from the atomically applied lotord bundle.
func (c *Client) ConfGet(board string, knownVersion uint64) (ConfBlob, error) {
	args := []value{vStr(board)}
	if knownVersion > 0 {
		args = append(args, vU64(knownVersion))
	}
	values, err := c.do(opCONFGET, args)
	if err != nil {
		return ConfBlob{}, err
	}
	result := ConfBlob{Board: board}
	if len(values) >= 6 {
		result.Changed = values[0].asBool()
		result.Board = values[1].asStr()
		result.Version = values[2].U64
		result.Etag = values[3].asStr()
		result.ContentType = values[4].asStr()
		if values[5].Kind == tagBytes {
			result.Payload = append([]byte(nil), values[5].Bytes...)
		}
	}
	return result, nil
}

// ConsumeResult is a METER.CONSUME outcome. On an overage-granted consume (Reason=="overage_granted"),
// BlocksPurchased and WalletBalance report the auto-bought overage and the wallet after the debit.
type ConsumeResult struct {
	Reason             string
	Evidence           string
	Remaining          int64
	Used               int64
	BlocksPurchased    int64 // overage blocks bought this consume (0 unless reason==overage_granted)
	WalletBalance      int64 // wallet balance after the overage debit
	GrantDrawn         int64 // one-time addon units drawn this consume (reason addon_granted/overage_granted)
	GrantRemaining     int64 // remaining one-time addon units after the draw
	Max                int64
	CompositionVersion uint64
	Accepted           bool
}

// MeterConsume records durable usage (idempotent when idempotencyKey is set). When the meter has an
// overage rule and the quota is exceeded, the consume auto-buys blocks from the wallet instead of
// rejecting (Reason=="overage_granted").
func (c *Client) MeterConsume(scope, meter string, n uint64, idempotencyKey string) (ConsumeResult, error) {
	args := []value{vAddr(scope), vStr(meter), vU64(n)}
	if idempotencyKey != "" {
		args = append(args, value{Kind: tagNull}, vStr(idempotencyKey)) // actor=null, idempotency_key
	}
	a, err := c.do(opMETERCONSUME, args)
	if err != nil {
		return ConsumeResult{}, err
	}
	r := ConsumeResult{}
	if len(a) >= 4 {
		r.Accepted = a[0].asNum() == 1
		r.Reason = a[1].asStr()
		r.Remaining = a[2].asNum()
		r.Used = a[3].asNum()
		if len(a) >= 5 {
			r.Max = a[4].asNum()
		}
	}
	if len(a) >= 8 { // overage-granted consume carries blocks_purchased + wallet_balance
		r.BlocksPurchased = a[6].asNum()
		r.WalletBalance = a[7].asNum()
	}
	if len(a) >= 10 { // a consume that drew one-time addon grants carries grant draw/remaining
		r.GrantDrawn = a[8].asNum()
		r.GrantRemaining = a[9].asNum()
	}
	if len(a) >= 8 && a[6].Kind == tagStr {
		r.Evidence = a[6].asStr()
		r.CompositionVersion = a[7].U64
	}
	return r, nil
}

type CompositionPin struct {
	Operation          string
	ResultHash         string
	PoolRef            string
	CompositionSubject string
	Version            uint64
}

func capacityPin(pin CompositionPin) value {
	values := map[string]value{
		"operation":           vStr(pin.Operation),
		"composition_hash":    vStr(pin.ResultHash),
		"composition_version": vU64(pin.Version),
	}
	if pin.PoolRef != "" {
		values["pool_ref"] = vStr(pin.PoolRef)
	}
	return vMap(values)
}

// MeterConsumePinned records usage against one exact canonical runtime composition.
func (c *Client) MeterConsumePinned(
	scope, meter string,
	n uint64,
	idempotencyKey string,
	pin CompositionPin,
) (ConsumeResult, error) {
	a, err := c.do(opMETERCONSUME, []value{
		vAddr(scope), vStr(meter), vU64(n), vNull(), vStr(idempotencyKey), capacityPin(pin),
	})
	if err != nil {
		return ConsumeResult{}, err
	}
	result := ConsumeResult{}
	if len(a) >= 6 {
		result.Accepted = a[0].asNum() == 1
		result.Reason = a[1].asStr()
		result.Remaining = a[2].asNum()
		result.Used = a[3].asNum()
		result.Max = a[4].asNum()
	}
	if len(a) >= 8 {
		result.Evidence = a[6].asStr()
		result.CompositionVersion = a[7].U64
	}
	return result, nil
}

func (c *Client) MeterReleasePinned(
	scope, meter string,
	n uint64,
	idempotencyKey string,
	pin CompositionPin,
) error {
	values, err := c.do(opMETERRELEASE, []value{
		vAddr(scope), vStr(meter), vU64(n), vStr(idempotencyKey), capacityPin(pin),
	})
	if err != nil {
		return err
	}
	if len(values) == 0 || !values[0].asBool() {
		reason := "capacity_release_denied"
		if len(values) >= 6 && values[5].asStr() != "" {
			reason = values[5].asStr()
		}
		return fmt.Errorf("meter release denied: %s", reason)
	}
	return nil
}

type SeatResult struct {
	Reason             string
	SeatID             string
	Evidence           string
	Used               int64
	Max                int64
	CompositionVersion uint64
	Outcome            int64
}

func (c *Client) SeatClaimPinned(
	scope, seatType, user, idempotencyKey string,
	pin CompositionPin,
) (SeatResult, error) {
	values, err := c.do(opSEATCLAIM, []value{
		vAddr(scope), vStr(seatType), vAddr(user), vStr(idempotencyKey), capacityPin(pin),
	})
	if err != nil {
		return SeatResult{}, err
	}
	return decodeSeatResult(values), nil
}

func (c *Client) SeatReleasePinned(
	scope, seatType, user string,
	pin CompositionPin,
) (SeatResult, error) {
	values, err := c.do(opSEATRELEASE, []value{
		vAddr(scope), vStr(seatType), vAddr(user), capacityPin(pin),
	})
	if err != nil {
		return SeatResult{}, err
	}
	result := SeatResult{}
	if len(values) >= 3 {
		if values[0].asBool() {
			result.Outcome = 1
		}
		result.Used = values[1].asNum()
	}
	if len(values) >= 5 {
		result.Evidence = values[3].asStr()
		result.CompositionVersion = values[4].U64
	}
	if len(values) >= 6 {
		result.Reason = values[5].asStr()
	}
	return result, nil
}

func decodeSeatResult(values []value) SeatResult {
	result := SeatResult{}
	if len(values) >= 6 {
		result.Outcome = values[0].asNum()
		result.Reason = values[1].asStr()
		result.Used = values[2].asNum()
		result.Max = values[3].asNum()
		result.SeatID = values[4].asStr()
	}
	if len(values) >= 8 {
		result.Evidence = values[6].asStr()
		result.CompositionVersion = values[7].U64
	}
	return result
}

// LifecycleResult is the durable outcome of a compound organization invitation/member operation.
// Used is always Active + Reserved for the selected seat pool.
type LifecycleResult struct {
	Reason             string
	InvitationID       string
	SeatID             string
	Evidence           string
	Active             int64
	Reserved           int64
	Used               int64
	Maximum            int64
	Remaining          int64
	LogSeq             uint64
	CompositionVersion uint64
	Accepted           bool
}

func decodeLifecycleResult(values []value) LifecycleResult {
	result := LifecycleResult{}
	if len(values) < 12 {
		return result
	}
	result.Accepted = values[0].asBool()
	result.Reason = values[1].asStr()
	result.InvitationID = values[2].asStr()
	result.SeatID = values[3].asStr()
	result.Active = values[4].asNum()
	result.Reserved = values[5].asNum()
	result.Used = values[6].asNum()
	result.Maximum = values[7].asNum()
	result.Remaining = values[8].asNum()
	result.LogSeq = values[9].U64
	result.Evidence = values[10].asStr()
	result.CompositionVersion = values[11].U64
	return result
}

type OrganizationInvitation struct {
	ID           string
	Invitee      string
	Role         string
	SeatID       string
	ExpiresAt    uint64
	SeatReserved bool
}

// InvitationCreatePinned creates an invitation and applies the active Seat Board lifecycle in one
// durable Lotor transition. Ticket is returned/delivered by the caller but only its SHA-256 digest
// is persisted by lotord.
func (c *Client) InvitationCreatePinned(
	scope, actor, invitationID, invitee, role, ticket string,
	expiresAt uint64,
	idempotencyKey string,
	pin CompositionPin,
) (LifecycleResult, error) {
	values, err := c.do(opINVITECREATE, []value{
		vAddr(scope), vAddr(actor), vStr(invitationID), vAddr(invitee), vStr(role), vStr(ticket),
		vU64(expiresAt), vStr(idempotencyKey), capacityPin(pin),
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return decodeLifecycleResult(values), nil
}

// InvitationAccept atomically consumes a ticket, binds the reserved seat to memberSubject, and
// grants membership/role access. It does not release and reclaim capacity.
func (c *Client) InvitationAccept(
	ticket, authenticatedInvitee, memberSubject, idempotencyKey string,
) (LifecycleResult, error) {
	values, err := c.do(opINVITEACCEPT, []value{
		vStr(ticket), vAddr(authenticatedInvitee), vAddr(memberSubject), vStr(idempotencyKey),
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return decodeLifecycleResult(values), nil
}

func (c *Client) InvitationCancel(
	scope, actor, invitationID, idempotencyKey string,
) (LifecycleResult, error) {
	values, err := c.do(opINVITECANCEL, []value{
		vAddr(scope), vAddr(actor), vStr(invitationID), vStr(idempotencyKey),
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return decodeLifecycleResult(values), nil
}

func (c *Client) InvitationList(scope string) ([]OrganizationInvitation, error) {
	values, err := c.do(opINVITELIST, []value{vAddr(scope)})
	if err != nil {
		return nil, err
	}
	if len(values) == 0 || values[0].Kind != tagList {
		return []OrganizationInvitation{}, nil
	}
	result := make([]OrganizationInvitation, 0, len(values[0].List))
	for _, value := range values[0].List {
		if value.Kind != tagMap {
			continue
		}
		result = append(result, OrganizationInvitation{
			ID:           value.Map["invitation_id"].asStr(),
			Invitee:      value.Map["invitee"].asStr(),
			Role:         value.Map["role"].asStr(),
			SeatID:       value.Map["seat_id"].asStr(),
			ExpiresAt:    value.Map["expires_at"].U64,
			SeatReserved: value.Map["seat_reserved"].asBool(),
		})
	}
	return result, nil
}

func (c *Client) MemberRemove(
	scope, actor, memberSubject, idempotencyKey string,
) (LifecycleResult, error) {
	values, err := c.do(opMEMBERREMOVE, []value{
		vAddr(scope), vAddr(actor), vAddr(memberSubject), vStr(idempotencyKey),
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return decodeLifecycleResult(values), nil
}

func (c *Client) MemberRoleSetPinned(
	scope, actor, memberSubject, role, idempotencyKey string,
	pin CompositionPin,
) (LifecycleResult, error) {
	values, err := c.do(opMEMBERROLESET, []value{
		vAddr(scope), vAddr(actor), vAddr(memberSubject), vStr(role), vStr(idempotencyKey), capacityPin(pin),
	})
	if err != nil {
		return LifecycleResult{}, err
	}
	return decodeLifecycleResult(values), nil
}

// AllowanceResult is an ALLOWANCE.GRANT outcome.
type AllowanceResult struct {
	Reason        string // "granted" | "insufficient_funds"
	UnitsTotal    int64  // remaining one-time addon units for the meter after the grant
	WalletBalance int64  // wallet balance after a credit-funded grant
	Accepted      bool   // false (reason insufficient_funds) when credit-funded and the wallet is short
}

// AllowanceGrant issues a one-time purchase addon: durable extra `units` of `meter` that carry across
// billing cycles until used up or `expiresAt` (epoch micros; 0 = never). Cost==0 + wallet=="" is a
// control-issued grant (paid via Stripe upstream); cost>0 funds it from a prepaid wallet (atomic
// debit + grant). Idempotent when idempotencyKey is set.
func (c *Client) AllowanceGrant(
	scope, meter string,
	units, expiresAt uint64,
	wallet string,
	cost uint64,
	idempotencyKey string,
) (AllowanceResult, error) {
	args := []value{vAddr(scope), vStr(meter), vU64(units), vU64(expiresAt), vStr(wallet), vU64(cost)}
	if idempotencyKey != "" {
		args = append(args, vStr(idempotencyKey))
	}
	a, err := c.do(opALLOWANCEGRANT, args)
	if err != nil {
		return AllowanceResult{}, err
	}
	r := AllowanceResult{}
	if len(a) >= 4 {
		r.Accepted = a[0].asNum() == 1
		r.Reason = a[1].asStr()
		r.UnitsTotal = a[2].asNum()
		r.WalletBalance = a[3].asNum()
	}
	return r, nil
}

// AllowanceBalance reads the remaining (non-expired) one-time addon units for a meter, and the live
// grant count.
func (c *Client) AllowanceBalance(scope, meter string) (remaining, grants int64, err error) {
	a, err := c.do(opALLOWANCEGET, []value{vAddr(scope), vStr(meter)})
	if err != nil {
		return 0, 0, err
	}
	if len(a) >= 2 {
		return a[0].asNum(), a[1].asNum(), nil
	}
	return 0, 0, nil
}

// MeterUsed returns the current usage for a counter (METER.GET) — for reconciliation.
func (c *Client) MeterUsed(scope, meter string) (int64, error) {
	a, err := c.do(opMETERGET, []value{vAddr(scope), vStr(meter)})
	if err != nil {
		return 0, err
	}
	if len(a) >= 1 {
		return a[0].asNum(), nil
	}
	return 0, nil
}

type MeterState struct {
	Evidence           string
	Interval           string
	Reason             string
	Used               int64
	Max                int64
	Remaining          int64
	CompositionVersion uint64
}

func (c *Client) MeterGetPinned(scope, meter string, pin CompositionPin) (MeterState, error) {
	values, err := c.do(opMETERGET, []value{vAddr(scope), vStr(meter), capacityPin(pin)})
	if err != nil {
		return MeterState{}, err
	}
	result := MeterState{}
	if len(values) >= 4 {
		result.Used = values[0].asNum()
		result.Max = values[1].asNum()
		result.Remaining = values[2].asNum()
		result.Interval = values[3].asStr()
	}
	if len(values) >= 10 {
		result.Evidence = values[8].asStr()
		result.CompositionVersion = values[9].U64
	}
	if len(values) >= 11 {
		result.Reason = values[10].asStr()
	}
	return result, nil
}

// dispatchEvent routes an EVENT frame to its subscription handler by watch_id (args:
// type, target, detail:map, log_seq, watch_id).
func (c *Client) dispatchEvent(f frame) {
	if len(f.args) < 5 {
		return
	}
	ev := Event{
		Type:    f.args[0].asStr(),
		Target:  f.args[1].asStr(),
		Detail:  numericMap(f.args[2]),
		LogSeq:  nonNegativeUint64(f.args[3].asNum()),
		WatchID: f.args[4].asStr(),
	}
	c.mu.Lock()
	h := c.subs[ev.WatchID]
	c.mu.Unlock()
	if h != nil {
		go h(ev) // off the read loop: a handler may call back into this client (which needs the loop free)
	}
}

func nonNegativeUint64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func numericMap(v value) map[string]int64 {
	out := map[string]int64{}
	if v.Kind == tagMap {
		for k, mv := range v.Map {
			out[k] = mv.asNum()
		}
	}
	return out
}

// Watch subscribes to change selectors; handler fires on each matching EVENT. Returns the watch id.
func (c *Client) Watch(selectors []string, handler func(Event)) (string, error) {
	items := make([]value, len(selectors))
	for i, s := range selectors {
		items[i] = vStr(s)
	}
	a, err := c.do(opWATCH, []value{{Kind: tagList, List: items}})
	if err != nil {
		return "", err
	}
	id := ""
	if len(a) >= 1 {
		id = a[0].asStr()
	}
	c.mu.Lock()
	c.subs[id] = handler
	c.mu.Unlock()
	return id, nil
}

// Unwatch cancels a subscription by its watch id.
func (c *Client) Unwatch(id string) error {
	c.mu.Lock()
	delete(c.subs, id)
	c.mu.Unlock()
	_, err := c.do(opUNWATCH, []value{vStr(id)})
	return err
}

// WalletLowEvent is a decoded wallet_low event.
type WalletLowEvent struct {
	Scope, Wallet      string
	Balance, Threshold int64
}

// OnWalletLow subscribes to the wallet_low firehose (all accounts on this tenant) and decodes each
// event — the control plane uses this to drive event-driven auto-reload. Returns the watch id.
func (c *Client) OnWalletLow(handler func(WalletLowEvent)) (string, error) {
	return c.Watch([]string{"wallet_low"}, func(ev Event) {
		if ev.Type != "wallet_low" {
			return
		}
		scope, wallet := ev.Target, ""
		if i := strings.LastIndex(ev.Target, "/"); i >= 0 {
			scope, wallet = ev.Target[:i], ev.Target[i+1:]
		}
		handler(WalletLowEvent{Scope: scope, Wallet: wallet, Balance: ev.Detail["balance"], Threshold: ev.Detail["threshold"]})
	})
}

// WalletResult is a WALLET.CREDIT / WALLET.DEBIT outcome.
type WalletResult struct {
	Reason   string // "credited" | "debited" | "insufficient_funds"
	Balance  int64  // balance after the op
	Accepted bool   // a debit rejected for insufficient funds is Accepted=false
}

// WalletCredit adds credits to a prepaid wallet (a top-up / the control plane's auto-reload).
// Idempotent when idempotencyKey is set — a retried reload never double-credits.
func (c *Client) WalletCredit(scope, wallet string, amount uint64, idempotencyKey string) (WalletResult, error) {
	return c.walletOp(opWALLETCREDIT, scope, wallet, amount, idempotencyKey)
}

// WalletDebit draws down a prepaid wallet on consumption; rejected (Accepted=false) if the balance
// is insufficient. Idempotent when idempotencyKey is set.
func (c *Client) WalletDebit(scope, wallet string, amount uint64, idempotencyKey string) (WalletResult, error) {
	return c.walletOp(opWALLETDEBIT, scope, wallet, amount, idempotencyKey)
}

func (c *Client) walletOp(opcode uint16, scope, wallet string, amount uint64, idem string) (WalletResult, error) {
	args := []value{vAddr(scope), vStr(wallet), vU64(amount)}
	if idem != "" {
		args = append(args, vStr(idem))
	}
	a, err := c.do(opcode, args)
	if err != nil {
		return WalletResult{}, err
	}
	r := WalletResult{}
	if len(a) >= 3 {
		r.Accepted = a[0].asNum() == 1
		r.Reason = a[1].asStr()
		r.Balance = a[2].asNum()
	}
	return r, nil
}

// WalletBalance reads a prepaid wallet's current balance (WALLET.GET) — used by the control plane's
// auto-reload poll to decide whether a top-up is due.
func (c *Client) WalletBalance(scope, wallet string) (int64, error) {
	a, err := c.do(opWALLETGET, []value{vAddr(scope), vStr(wallet)})
	if err != nil {
		return 0, err
	}
	if len(a) >= 1 {
		return a[0].asNum(), nil
	}
	return 0, nil
}

// Done is closed when the connection drops (read loop exits) — callers maintaining a long-lived
// subscription (e.g. the control plane watching wallet_low) select on it to re-dial.
func (c *Client) Done() <-chan struct{} { return c.closed }

func (c *Client) Close() error { return c.conn.Close() }

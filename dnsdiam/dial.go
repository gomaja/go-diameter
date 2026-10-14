package dnsdiam

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/peer"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
)

// DialConfig configures a fresh sm.Client for each candidate. Handler receives
// application messages only after successful discovery admission, through an
// expiry-checked Conn. Settings.OnHandshake runs after the same validation.
// Clock and the Discoverer's Now may be replaced together in tests.
type DialConfig struct {
	Settings           sm.Settings
	Policy             Policy
	Handler            diam.Handler
	Clock              peer.Clock
	ReadTimeout        time.Duration
	WriteTimeout       time.Duration
	MaxRetransmits     uint
	RetransmitInterval time.Duration
	EnableWatchdog     bool
	WatchdogInterval   time.Duration
}

// DialContext discovers, connects and validates CER/CEA before returning a
// usable connection (RFC 6733 §§5.2, 13.1–13.2). It tries candidates and their
// literal addresses in discovery order. Canceling ctx after success has no
// effect. The returned connection expires at the earliest DNS/certificate
// deadline; callers rediscover and dial again to refresh it.
// Write and WriteStream accept complete Diameter frames (Message.WriteTo),
// enforcing the discovered application and requested destination realm.
func (d *Discoverer) DialContext(ctx context.Context, request Request, cfg DialConfig) (diam.Conn, error) {
	candidates, err := d.Discover(ctx, request)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, candidate := range candidates {
		spec, err := cfg.Policy.prepare(candidate, d.cfg.Now)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, endpoint := range spec.Peer.Endpoints {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			conn, err := d.dialCandidate(ctx, spec, endpoint, cfg)
			if err == nil {
				return conn, nil
			}
			failures = append(failures, err)
		}
	}
	return nil, errors.Join(append([]error{ErrNoService}, failures...)...)
}

func (d *Discoverer) dialCandidate(ctx context.Context, spec peer.Discovery, endpoint peer.Endpoint, cfg DialConfig) (diam.Conn, error) {
	remaining := spec.ExpiresAt.Sub(d.cfg.Now())
	if remaining <= 0 {
		return nil, ErrExpired
	}
	dialContext, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()
	ctx = dialContext
	settings := cfg.Settings
	userHandshake := settings.OnHandshake
	type result struct {
		conn *expiryConn
		err  error
	}
	var admission atomic.Pointer[result]
	guard := func(c diam.Conn) *expiryConn {
		value := admission.Load()
		if value == nil || value.conn == nil || value.conn.Closed() {
			c.Close()
			return nil
		}
		return value.conn
	}
	hook := func(user diam.HandlerFunc) diam.HandlerFunc {
		return func(c diam.Conn, m *diam.Message) {
			if checked := guard(c); checked != nil && user != nil {
				user(checked, m)
			}
		}
	}
	settings.OnCER = hook(settings.OnCER)
	settings.OnCEA = hook(settings.OnCEA)
	settings.OnDWR = hook(settings.OnDWR)
	settings.OnDWA = hook(settings.OnDWA)
	if user := settings.OnDPR; user != nil {
		settings.OnDPR = func(c diam.Conn, cause sm.DisconnectCause) {
			if checked := guard(c); checked != nil {
				user(checked, cause)
			}
		}
	}
	if user := settings.OnWatchdogConnEvent; user != nil {
		settings.OnWatchdogConnEvent = func(c diam.Conn, event sm.WatchdogEvent) {
			if checked := guard(c); checked != nil {
				user(checked, event)
			}
		}
	}
	if user := settings.OnProtocolError; user != nil {
		settings.OnProtocolError = func(event diam.ProtocolErrorEvent) {
			value := admission.Load()
			if value != nil && value.conn != nil {
				event.Conn = value.conn
			} else if event.Conn != nil {
				event.Conn = unadmittedConn{event.Conn}
			}
			user(event)
		}
	}
	settings.OnHandshake = func(c diam.Conn, meta *smpeer.Metadata) {
		expires, err := spec.Validate(c, meta)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			admission.Store(&result{err: err})
			c.Close()
			return
		}
		admitted := &expiryConn{Conn: c, expires: expires, now: d.cfg.Now, application: spec.ApplicationIDs[0], realm: string(spec.Realm)}
		admission.Store(&result{conn: admitted})
		admitted.arm(cfg.Clock)
		if ctx.Err() != nil {
			admitted.Close()
			return
		}
		if userHandshake != nil {
			userHandshake(admitted, meta.Clone())
		}
	}
	machine, err := sm.New(&settings)
	if err != nil {
		return nil, err
	}
	// StateMachine holds the CEA dispatch barrier through OnHandshake, so this
	// closure cannot observe an uninitialized admission result.
	machine.HandleFunc("ALL", func(c diam.Conn, m *diam.Message) {
		admitted := admission.Load()
		if admitted == nil || admitted.conn == nil || admitted.conn.Closed() {
			c.Close()
			return
		}
		if m.Header.ApplicationID != 0 {
			allowed := false
			for _, app := range spec.ApplicationIDs {
				if app == m.Header.ApplicationID {
					allowed = true
				}
			}
			if !allowed {
				c.Close()
				return
			}
		}
		if cfg.Handler != nil {
			if admitted.conn.Closed() {
				c.Close()
				return
			}
			cfg.Handler.ServeDIAM(admitted.conn, m)
		}
	})
	client := &sm.Client{Dict: settings.Dict, Handler: machine, TLSConfig: endpoint.TLSConfig, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout, MaxRetransmits: cfg.MaxRetransmits, RetransmitInterval: cfg.RetransmitInterval, EnableWatchdog: cfg.EnableWatchdog, WatchdogInterval: cfg.WatchdogInterval}
	var conn diam.Conn
	if endpoint.TLSConfig != nil {
		conn, err = client.DialTLSContext(ctx, endpoint.Network, endpoint.Address, "", "", nil)
	} else {
		conn, err = client.DialContext(ctx, endpoint.Network, endpoint.Address, nil)
	}
	if err != nil {
		if admitted := admission.Load(); admitted != nil && admitted.conn != nil {
			admitted.conn.Close()
		}
		return nil, err
	}
	admitted := admission.Load()
	if admitted != nil && admitted.err != nil {
		conn.Close()
		return nil, admitted.err
	}
	if admitted == nil || admitted.conn == nil || admitted.conn.Closed() {
		conn.Close()
		return nil, ErrExpired
	}
	return admitted.conn, nil
}

type expiryConn struct {
	diam.Conn
	expires     time.Time
	now         func() time.Time
	application uint32
	realm       string
	mu          sync.Mutex
	timer       peer.Timer
	closed      bool
}

type unadmittedConn struct{ diam.Conn }

func (c unadmittedConn) Unwrap() diam.Conn                     { return c.Conn }
func (c unadmittedConn) Write([]byte) (int, error)             { return 0, ErrUnauthorized }
func (c unadmittedConn) WriteStream([]byte, uint) (int, error) { return 0, ErrUnauthorized }

func (c *expiryConn) Unwrap() diam.Conn { return c.Conn }
func (c *expiryConn) arm(clock peer.Clock) {
	duration := c.expires.Sub(c.now())
	var timer peer.Timer
	if clock == nil {
		timer = time.AfterFunc(duration, c.Close)
	} else {
		timer = clock.AfterFunc(duration, c.Close)
	}
	c.mu.Lock()
	if c.closed {
		timer.Stop()
	} else {
		c.timer = timer
	}
	c.mu.Unlock()
	if notifier, ok := diam.ConnAs[diam.CloseNotifier](c.Conn); ok {
		go func() { <-notifier.CloseNotify(); c.Close() }()
	}
}
func (c *expiryConn) Close() {
	c.mu.Lock()
	c.closed = true
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	c.Conn.Close()
}
func (c *expiryConn) Closed() bool { return !c.now().Before(c.expires) || c.Conn.Closed() }
func (c *expiryConn) Write(p []byte) (int, error) {
	if c.Closed() {
		c.Close()
		return 0, ErrExpired
	}
	if err := c.scopeWrite(p); err != nil {
		return 0, err
	}
	if c.Closed() {
		c.Close()
		return 0, ErrExpired
	}
	return c.Conn.Write(p)
}
func (c *expiryConn) WriteStream(p []byte, stream uint) (int, error) {
	if c.Closed() {
		c.Close()
		return 0, ErrExpired
	}
	if err := c.scopeWrite(p); err != nil {
		return 0, err
	}
	if c.Closed() {
		c.Close()
		return 0, ErrExpired
	}
	return c.Conn.WriteStream(p, stream)
}

// Whole frames (as emitted by Message.WriteTo) permit application/realm scope
// checks before any bytes are sent. Fragmented raw writes are rejected.
func (c *expiryConn) scopeWrite(p []byte) error {
	for len(p) > 0 {
		header, err := diam.DecodeHeader(p)
		if err != nil || header.MessageLength < diam.HeaderLength || uint64(header.MessageLength) > uint64(len(p)) {
			return ErrInvalid
		}
		if header.ApplicationID != 0 && header.ApplicationID != c.application {
			return ErrUnauthorized
		}
		frame := p[:int(header.MessageLength)]
		message, err := diam.ReadMessage(bytes.NewReader(frame), c.Dictionary())
		if err != nil {
			return errors.Join(ErrInvalid, err)
		}
		realms, err := message.FindAVPs(avp.DestinationRealm, 0)
		if err != nil && !errors.Is(err, diam.ErrAVPNotFound) {
			return errors.Join(ErrInvalid, err)
		}
		if header.ApplicationID != 0 && header.CommandFlags&diam.RequestFlag != 0 && len(realms) != 1 {
			return ErrUnauthorized
		}
		for _, realm := range realms {
			value, ok := realm.Data.(datatype.DiameterIdentity)
			name, err := absolute(string(value), false)
			if !ok || err != nil || identityName(name) != identityName(c.realm) {
				return ErrUnauthorized
			}
		}
		p = p[len(frame):]
	}
	return nil
}

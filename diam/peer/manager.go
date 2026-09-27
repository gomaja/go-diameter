// Package peer provides opt-in, statically configured Diameter peer management.
// It owns the RFC 6733 §5.6 base-message state machine on bound connections.
package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/base"
	"github.com/gomaja/go-diameter/diam/sm"
	"github.com/gomaja/go-diameter/diam/sm/smparser"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
	"github.com/gomaja/go-sctp"
)

// Clock schedules peer timeouts. Callbacks only enqueue events.
type Clock interface {
	AfterFunc(time.Duration, func()) Timer
}
type Timer interface{ Stop() bool }
type realClock struct{}

func (realClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

type Timers struct{ Tc, TwInit, Connect, CER, Closing time.Duration }
type Limits struct{ Events int }
type DialFunc func(context.Context, Endpoint) (net.Conn, error)
type Endpoint struct {
	Network, Address string
	TLSConfig        *tls.Config
}
type PeerConfig struct {
	Host            datatype.DiameterIdentity
	Endpoints       []Endpoint
	NoAutoReconnect bool
}
type Config struct {
	Settings sm.Settings
	Clock    Clock
	Timers   Timers
	Limits   Limits
	Dial     DialFunc
	// OnPeerEvent is observational. Calling Close from this callback is safe.
	// Events are dropped when its bounded queue is full; Peers returns the
	// current state independently.
	OnPeerEvent    func(PeerEvent)
	watchdogTiming *watchdogTiming // test-only short Tw and deterministic jitter
}
type PeerSnapshot struct {
	Host, Realm  datatype.DiameterIdentity
	Applications []uint32
	State        PeerState
	Generation   uint64
	Watchdog     WatchdogState
	Eligible     bool
}
type PeerEvent struct {
	Peer   PeerSnapshot
	Reason error
}

type Manager struct {
	cfg              Config
	mu               sync.RWMutex
	peers            map[string]*actor
	sessions         map[diam.Conn]*session
	server           *diam.Server
	started, closing bool
	runCtx           context.Context
	done             chan struct{}
	closed           chan struct{}
	wg               sync.WaitGroup
	callbackQ        chan PeerEvent
	errors           *diam.ServeMux
}

func New(cfg Config) (*Manager, error) {
	if len(cfg.Settings.OriginHost) == 0 || len(cfg.Settings.OriginRealm) == 0 {
		return nil, errors.New("peer: Origin-Host and Origin-Realm are required")
	}
	cfg.Settings.HostIPAddresses = append([]datatype.Address(nil), cfg.Settings.HostIPAddresses...)
	if cfg.Clock == nil {
		cfg.Clock = realClock{}
	}
	if cfg.Timers.TwInit == 0 {
		cfg.Timers.TwInit = 30 * time.Second
	}
	floor := 6 * time.Second
	if cfg.watchdogTiming != nil {
		floor = cfg.watchdogTiming.floor
	}
	if cfg.Timers.TwInit < floor {
		return nil, fmt.Errorf("peer: TwInit %s below RFC 3539 §3.4.1 minimum %s", cfg.Timers.TwInit, floor)
	}
	if cfg.Timers.Tc == 0 {
		cfg.Timers.Tc = 30 * time.Second
	}
	if cfg.Timers.Tc < 0 {
		return nil, errors.New("peer: Tc must be positive")
	}
	if cfg.Timers.Connect <= 0 {
		cfg.Timers.Connect = 5 * time.Second
	}
	if cfg.Timers.CER <= 0 {
		cfg.Timers.CER = 5 * time.Second
	}
	if cfg.Timers.Closing <= 0 {
		cfg.Timers.Closing = 5 * time.Second
	}
	if cfg.Limits.Events <= 0 {
		cfg.Limits.Events = 64
	}
	m := &Manager{cfg: cfg, peers: make(map[string]*actor), sessions: make(map[diam.Conn]*session), done: make(chan struct{}), closed: make(chan struct{}), callbackQ: make(chan PeerEvent, cfg.Limits.Events), errors: diam.NewServeMux()}
	go m.deliverEvents()
	return m, nil
}

func identity(s datatype.DiameterIdentity) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
func compareIdentity(a, b datatype.DiameterIdentity) int {
	return strings.Compare(identity(a), identity(b))
}

func (m *Manager) AddPeer(cfg PeerConfig) error {
	if len(cfg.Host) == 0 {
		return errors.New("peer: empty peer Host")
	}
	copyCfg := PeerConfig{Host: cfg.Host, Endpoints: make([]Endpoint, len(cfg.Endpoints)), NoAutoReconnect: cfg.NoAutoReconnect}
	for i, e := range cfg.Endpoints {
		if e.Address == "" {
			return fmt.Errorf("peer: empty endpoint address for %s", cfg.Host)
		}
		switch e.Network {
		case "", "tcp", "tcp4", "tcp6", "sctp", "sctp4", "sctp6":
		default:
			return fmt.Errorf("peer: unsupported network %q", e.Network)
		}
		if e.TLSConfig != nil && strings.HasPrefix(e.Network, "sctp") {
			return errors.New("peer: TLS/SCTP is unsupported")
		}
		copyCfg.Endpoints[i] = e
		if e.TLSConfig != nil {
			copyCfg.Endpoints[i].TLSConfig = e.TLSConfig.Clone()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started || m.closing {
		return errors.New("peer: AddPeer after Start or Close")
	}
	key := identity(cfg.Host)
	if key == identity(m.cfg.Settings.OriginHost) {
		return errors.New("peer: local and peer Origin-Host collide")
	}
	if _, ok := m.peers[key]; ok {
		return fmt.Errorf("peer: duplicate Host %s", cfg.Host)
	}
	a := &actor{m: m, cfg: copyCfg, events: make(chan event, m.cfg.Limits.Events), done: make(chan struct{}), state: Closed, watchdog: WatchdogInitial}
	a.publish(nil)
	m.peers[key] = a
	m.wg.Add(1)
	go a.run()
	return nil
}

// BindServer installs the manager before Serve and preserves existing hooks.
func (m *Manager) BindServer(s *diam.Server) error {
	if s == nil {
		return errors.New("peer: nil Server")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.server != nil || m.closing {
		return errors.New("peer: Server already bound or manager closed")
	}
	managerDict, serverDict := m.cfg.Settings.Dict, s.Dict
	if managerDict == nil {
		managerDict = dict.Default
	}
	if serverDict == nil {
		serverDict = dict.Default
	}
	if managerDict != serverDict { // RFC 6733 §5.3: validate CER and advertise CEA applications from one dictionary.
		return errors.New("peer: Server dictionary differs from manager dictionary")
	}
	if err := s.ConfigureHandlerBeforeServe(m, m.acceptConnection, m.shutdownConnection); err != nil {
		return err
	}
	m.server = s
	return nil
}

func (m *Manager) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.started || m.closing {
		m.mu.Unlock()
		return errors.New("peer: already started or closed")
	}
	m.started = true
	m.runCtx = ctx
	actors := make([]*actor, 0, len(m.peers))
	for _, a := range m.peers {
		actors = append(actors, a)
	}
	m.mu.Unlock()
	for _, a := range actors {
		if len(a.cfg.Endpoints) > 0 {
			a.post(event{kind: start})
		}
	}
	return nil
}
func (m *Manager) Peers() []PeerSnapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]PeerSnapshot, 0, len(m.peers))
	for _, a := range m.peers {
		out = append(out, a.snapshot())
	}
	// A stable order keeps health and test snapshots deterministic.
	sortSnapshots(out)
	return out
}
func sortSnapshots(p []PeerSnapshot) {
	for i := 1; i < len(p); i++ {
		for j := i; j > 0 && identity(p[j].Host) < identity(p[j-1].Host); j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

func (m *Manager) Close(ctx context.Context, cause sm.DisconnectCause) error {
	m.mu.Lock()
	if m.closing {
		m.mu.Unlock()
		select {
		case <-m.closed:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	m.closing = true
	actors := make([]*actor, 0, len(m.peers))
	for _, a := range m.peers {
		actors = append(actors, a)
	}
	m.mu.Unlock()
	for _, a := range actors {
		a.post(event{kind: stop, cause: cause})
	}
	finished := make(chan struct{})
	go func() {
		for _, a := range m.allActors() {
			<-a.done
		}
		m.closeSessions()
		close(m.done)
		m.wg.Wait()
		close(m.closed)
		close(finished)
	}()
	select {
	case <-finished:
		return nil
	case <-ctx.Done():
		m.forceClose()
		return ctx.Err()
	}
}
func (m *Manager) allActors() []*actor {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*actor, 0, len(m.peers))
	for _, a := range m.peers {
		out = append(out, a)
	}
	return out
}
func (m *Manager) startContext() context.Context {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.runCtx != nil {
		return m.runCtx
	}
	return context.Background()
}
func (m *Manager) hasStarted() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.started
}
func (m *Manager) closeSessions() {
	m.mu.RLock()
	ss := make([]*session, 0, len(m.sessions))
	for _, s := range m.sessions {
		ss = append(ss, s)
	}
	m.mu.RUnlock()
	for _, s := range ss {
		s.close()
	}
}
func (m *Manager) forceClose() {
	m.closeSessions()
	for _, a := range m.allActors() {
		a.post(event{kind: timeout})
	}
}
func (m *Manager) Error(e *diam.ErrorReport)              { m.errors.Error(e) }
func (m *Manager) ErrorReports() <-chan *diam.ErrorReport { return m.errors.ErrorReports() }
func (m *Manager) report(s *session, msg *diam.Message, err error) {
	if err == nil {
		return
	}
	var c diam.Conn
	if s != nil {
		c = s.c
	}
	m.Error(&diam.ErrorReport{Conn: c, Message: msg, Error: err})
	if s != nil {
		if a, _ := s.binding(); a != nil {
			a.notify(err)
		}
	}
}
func (m *Manager) deliverEvents() {
	for {
		select {
		case <-m.done:
			return
		default:
		}
		select {
		case e := <-m.callbackQ:
			if m.cfg.OnPeerEvent != nil {
				func() { defer func() { _ = recover() }(); m.cfg.OnPeerEvent(e) }()
			}
		case <-m.done:
			return
		}
	}
}
func (m *Manager) notify(e PeerEvent) {
	select {
	case m.callbackQ <- e:
	default:
	}
}

func (m *Manager) unregister(s *session) { m.mu.Lock(); delete(m.sessions, s.c); m.mu.Unlock() }
func (m *Manager) getSession(c diam.Conn) *session {
	m.mu.RLock()
	s := m.sessions[c]
	m.mu.RUnlock()
	return s
}
func (m *Manager) acceptConnection(c diam.Conn) {
	s := m.newSession(c, nil, 0, true)
	if s == nil {
		return
	}
	s.firstMu.Lock()
	s.preTimer = m.cfg.Clock.AfterFunc(m.cfg.Timers.CER, func() {
		s.firstMu.Lock()
		waiting := !s.first
		s.firstMu.Unlock()
		if waiting {
			m.report(s, nil, errors.New("peer: pre-CER timeout"))
			s.close()
		}
	})
	select {
	case <-s.closed:
		s.preTimer.Stop()
	default:
	}
	s.firstMu.Unlock()
}
func (m *Manager) shutdownConnection(ctx context.Context, c diam.Conn) {
	s := m.getSession(c)
	if s == nil {
		return
	}
	a, _ := s.binding()
	if a == nil {
		return
	}
	a.post(event{kind: stop, cause: sm.DisconnectRebooting})
	select {
	case <-s.closed:
	case <-ctx.Done():
		s.close()
	}
}
func (m *Manager) ServeDIAM(c diam.Conn, msg *diam.Message) {
	s := m.getSession(c)
	if s == nil {
		c.Close()
		return
	}
	if !s.enqueue(msg) {
		m.report(s, msg, errors.New("peer: ordered ingress queue full"))
		s.close()
	}
}
func (m *Manager) processDIAM(s *session, msg *diam.Message) {
	c := s.c
	if s.inbound {
		s.firstMu.Lock()
		if s.rejectingFirst {
			s.firstMu.Unlock()
			return
		}
		first := !s.first
		if first {
			s.first = true
			if s.preTimer != nil {
				s.preTimer.Stop()
			}
		}
		s.firstMu.Unlock()
		if first {
			// RFC 6733 §5.6.1: pre-CER admission accepts only a CER.
			if msg.Header.ApplicationID != 0 || msg.Header.CommandCode != diam.CapabilitiesExchange || msg.Header.CommandFlags&diam.RequestFlag == 0 {
				m.report(s, msg, errors.New("peer: first inbound message is not CER"))
				s.close()
				return
			}
			var name struct {
				OriginHost datatype.DiameterIdentity `avp:"Origin-Host"`
			}
			if err := msg.Unmarshal(&name); err != nil || len(name.OriginHost) == 0 {
				m.rejectCER(s, msg, diam.UnableToComply, errors.New("peer: missing or malformed Origin-Host"))
				return
			}
			m.mu.RLock()
			a := m.peers[identity(name.OriginHost)]
			m.mu.RUnlock()
			if a == nil { // RFC 6733 §5.3: unknown CER may receive 3010, then transport closes.
				m.rejectCER(s, msg, diam.UnknownPeer, fmt.Errorf("peer: unknown Origin-Host %s", name.OriginHost))
				return
			}
			cer := new(smparser.CER)
			_, err := cer.ParseWithSecurity(msg, smparser.Server, c.TLS() != nil)
			if err != nil {
				code := uint32(diam.UnableToComply)
				if errors.Is(err, base.ErrNoCommonApplication) {
					code = diam.NoCommonApplication
				}
				if errors.Is(err, base.ErrNoCommonSecurity) {
					code = diam.NoCommonSecurity
				}
				m.rejectCER(s, msg, code, err)
				return
			}
			s.bind(a, 0)
			a.post(event{kind: rConnCER, s: s, msg: msg, meta: smpeer.FromCER(cer).Clone()})
			return
		}
	}
	a, _ := s.binding()
	if a == nil {
		m.report(s, msg, errors.New("peer: unbound connection message"))
		s.close()
		return
	}
	a.post(event{kind: wireEvent, s: s, msg: msg})
}
func (m *Manager) rejectCER(s *session, msg *diam.Message, code uint32, reason error) {
	cfg := m.baseSettings(s.c)
	answer := base.BuildCEA(msg, cfg, code)
	m.report(s, msg, reason)
	if !s.send(answer, true) {
		s.close()
	}
}
func (m *Manager) baseSettings(c diam.Conn) base.Settings {
	cfg := base.Settings{OriginHost: m.cfg.Settings.OriginHost, OriginRealm: m.cfg.Settings.OriginRealm, VendorID: m.cfg.Settings.VendorID, ProductName: m.cfg.Settings.ProductName, OriginStateID: m.cfg.Settings.OriginStateID, FirmwareRevision: m.cfg.Settings.FirmwareRevision, HostIPAddresses: append([]datatype.Address(nil), m.cfg.Settings.HostIPAddresses...)}
	if len(cfg.HostIPAddresses) == 0 && c != nil {
		switch addr := c.LocalAddr().(type) {
		case *net.TCPAddr:
			if addr != nil && addr.IP != nil {
				cfg.HostIPAddresses = []datatype.Address{datatype.Address(addr.IP)}
			}
		case *sctp.Addr:
			if addr != nil {
				for _, ip := range addr.IPs {
					cfg.HostIPAddresses = append(cfg.HostIPAddresses, datatype.Address(net.IP(ip.AsSlice())))
				}
			}
		}
	}
	if len(cfg.HostIPAddresses) == 0 {
		cfg.HostIPAddresses = []datatype.Address{datatype.Address(net.IPv4(127, 0, 0, 1))}
	}
	dictionary := m.cfg.Settings.Dict
	if dictionary == nil {
		dictionary = dict.Default
	}
	for _, app := range sm.PrepareSupportedApps(dictionary) {
		cfg.Applications = append(cfg.Applications, base.LocalApplication{ID: app.ID, AppType: app.AppType, Vendor: app.Vendor})
		id := diam.NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unsigned32(app.ID))
		if app.AppType == "acct" {
			id = diam.NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unsigned32(app.ID))
		}
		if app.Vendor != 0 {
			group := &diam.GroupedAVP{AVP: []*diam.AVP{diam.NewAVP(avp.VendorID, avp.Mbit, 0, datatype.Unsigned32(app.Vendor)), id}}
			cfg.VendorSpecificApplicationID = append(cfg.VendorSpecificApplicationID, diam.NewAVP(avp.VendorSpecificApplicationID, avp.Mbit, 0, group))
		} else if app.AppType == "acct" {
			cfg.AcctApplicationID = append(cfg.AcctApplicationID, id)
		} else {
			cfg.AuthApplicationID = append(cfg.AuthApplicationID, id)
		}
	}
	return cfg
}
func (m *Manager) unsupported(s *session, msg *diam.Message) {
	// RFC 6733 §§7.1.3, 7.2: unsupported requests receive E-bit 3001; answers are reported and discarded.
	if msg.Header.CommandFlags&diam.RequestFlag != 0 {
		answer, err := base.BuildErrorAnswer(msg, m.baseSettings(s.c), diam.CommandUnsupported, nil, true)
		if err == nil {
			if !s.send(answer, false) {
				err = errors.New("peer: write queue full")
			}
		}
		m.report(s, msg, err)
	}
	m.report(s, msg, fmt.Errorf("peer: unhandled message %d/%d", msg.Header.ApplicationID, msg.Header.CommandCode))
}
func (m *Manager) HandleMessageError(c diam.Conn, msg *diam.Message, me *diam.MessageError) error {
	s := m.getSession(c)
	if s == nil {
		return nil
	}
	s.firstMu.Lock()
	preCER := s.inbound && !s.first
	if preCER {
		s.first = true
		if msg != nil && msg.Header != nil && me != nil && msg.Header.ApplicationID == 0 && msg.Header.CommandCode == diam.CapabilitiesExchange && msg.Header.CommandFlags&diam.RequestFlag != 0 {
			s.rejectingFirst = true
		}
		if s.preTimer != nil {
			s.preTimer.Stop()
			s.preTimer = nil
		}
	}
	s.firstMu.Unlock()
	if preCER { // RFC 6733 §5.6.1: discard malformed pre-CER traffic and close the connection.
		if msg == nil || msg.Header == nil || me == nil || msg.Header.ApplicationID != 0 || msg.Header.CommandCode != diam.CapabilitiesExchange || msg.Header.CommandFlags&diam.RequestFlag == 0 {
			s.close()
			return nil
		}
		answer, err := base.BuildErrorAnswer(msg, m.baseSettings(c), me.ResultCode, nil, me.ResultCode >= 3000 && me.ResultCode < 4000)
		if err != nil {
			s.close()
			return err
		}
		if !s.send(answer, true) {
			s.close()
			return errors.New("peer: write queue full")
		}
		return nil
	}
	if msg == nil || me == nil || msg.Header == nil {
		return nil
	}
	if msg.Header.CommandFlags&diam.RequestFlag == 0 {
		return nil
	}
	answer, err := base.BuildErrorAnswer(msg, m.baseSettings(c), me.ResultCode, nil, me.ResultCode >= 3000 && me.ResultCode < 4000)
	if err != nil {
		return err
	}
	if !s.send(answer, false) {
		return errors.New("peer: write queue full")
	}
	return nil
}

var _ diam.Handler = (*Manager)(nil)
var _ diam.MessageErrorHandler = (*Manager)(nil)

package peer

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// Route maps an exact Destination-Realm and header Application-Id to ordered peers.
type Route struct {
	Realm         datatype.DiameterIdentity
	ApplicationID uint32
	PeerHosts     []datatype.DiameterIdentity
}

type routeKey struct {
	realm string
	app   uint32
}
type routeTable struct{ entries map[routeKey][]string }

// SetRoutes validates a complete replacement and publishes it as one snapshot.
// RFC 6733 §2.7, Verified Erratum 3806: route entries name peers present in
// the peer table. Matching is exact after DNS ASCII case folding.
func (m *Manager) SetRoutes(routes []Route) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closing {
		return errors.New("peer: manager closed")
	}
	next := &routeTable{entries: make(map[routeKey][]string, len(routes))}
	for _, r := range routes {
		realm := identity(r.Realm)
		if realm == "" || strings.ContainsAny(realm, "* ") {
			return fmt.Errorf("peer: invalid route realm %q", r.Realm)
		}
		key := routeKey{realm: realm, app: r.ApplicationID}
		if _, exists := next.entries[key]; exists {
			return fmt.Errorf("peer: duplicate route for %s/%d", r.Realm, r.ApplicationID)
		}
		if len(r.PeerHosts) == 0 {
			return fmt.Errorf("peer: route %s/%d has no peers", r.Realm, r.ApplicationID)
		}
		seen := make(map[string]bool, len(r.PeerHosts))
		peers := make([]string, 0, len(r.PeerHosts))
		for _, host := range r.PeerHosts {
			name := identity(host)
			if name == "" || seen[name] {
				return fmt.Errorf("peer: empty or duplicate route peer %q", host)
			}
			if _, ok := m.peers[name]; !ok {
				return fmt.Errorf("peer: unknown route peer %q", host)
			}
			seen[name] = true
			peers = append(peers, name)
		}
		next.entries[key] = peers
	}
	m.routes.Store(next)
	return nil
}

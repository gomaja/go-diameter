package sm

import "github.com/gomaja/go-diameter/diam"

func pendingRequests(c diam.Conn) *diam.PendingRequests {
	if tracker, ok := diam.ConnAs[interface{ PendingRequests() *diam.PendingRequests }](c); ok {
		return tracker.PendingRequests()
	}
	return nil
}

func completePendingAnswer(c diam.Conn, m *diam.Message) bool {
	if requests := pendingRequests(c); requests != nil {
		return requests.MatchAnswer(m, true)
	}
	return false
}

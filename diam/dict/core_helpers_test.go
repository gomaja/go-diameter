package dict

import "testing"

// mustRegister registers avps in app and fails the test on error.
func mustRegister(t *testing.T, p *Parser, app uint32, avps ...*AVP) {
	t.Helper()
	if err := p.RegisterAVP(app, avps...); err != nil {
		t.Fatal(err)
	}
}
func newTestParser(t testing.TB, dictionaries ...Dictionary) *Parser {
	t.Helper()
	p, err := New(dictionaries...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

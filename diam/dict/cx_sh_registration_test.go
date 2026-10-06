package dict

import (
	"bytes"
	"errors"
	"testing"
)

func TestCxShScopeWithoutDeclaredSh(t *testing.T) {
	p := New(Base, NASREQ, Cx)
	if _, err := p.App(16777217); !errors.Is(err, ErrApplicationUnsupported) {
		t.Fatalf("Sh must remain undeclared: %v", err)
	}
	for _, code := range []uint32{621, 622, 623, 624, 625, 626, 648, 649, 650, 651, 652} {
		want, err := p.FindAVP(16777216, code)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := p.FindAVP(16777217, code); err != nil || got != want {
			t.Errorf("undeclared Sh code %d = %v, %v; want %s", code, got, err, want.Name)
		}
	}
}

func TestCxShScopeSnapshotSurvivesRegistration(t *testing.T) {
	p := New(Base, NASREQ, Cx, Sh)
	before := p.Snapshot()
	mustRegister(t, p, 16777217, vendorAVP("Test-Unrelated-Sh", 70000, "UTF8String"))
	after := p.Snapshot()
	if after == before {
		t.Fatal("registration did not publish a new Snapshot")
	}
	for _, app := range []uint32{16777216, 16777217} {
		for _, code := range []uint32{621, 622, 623, 624, 625, 626, 648, 649, 650, 651, 652} {
			want, err := before.FindAVP(app, code)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range []*Snapshot{before, after} {
				if got, err := s.FindAVP(app, code); err != nil || got != want {
					t.Errorf("app %d code %d changed across registration: %v, %v; want %s", app, code, got, err, want.Name)
				}
			}
		}
	}
	if _, err := before.FindAVPByCode(16777217, 70000, testVendor); err == nil {
		t.Error("earlier Snapshot sees the later registration")
	}
	assertNoWildcardRegistrations(t, after)
}

// RegisterAVP never assigns a vendor-agnostic code slot (RFC 6733 §4.1).
// A Sh registration remains vendor scoped after Cx is loaded.
func TestCxShScopeDoesNotPromoteRegistration(t *testing.T) {
	p := New(Base, NASREQ)
	mustRegister(t, p, 16777217, &AVP{
		Name: "Test-Sh-Collision", Code: 621, VendorID: 10415,
		Must: "V", Data: Data{TypeName: "UTF8String"},
	})
	before := p.Snapshot()
	registered, err := before.FindAVPByCode(16777217, 621, 10415)
	if err != nil {
		t.Fatal(err)
	}
	originalBare, err := before.FindAVP(16777217, uint32(621))
	if err != nil {
		t.Fatal(err)
	}
	data, err := bundledFS.ReadFile("bundled/" + string(Cx))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Load(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	if got, err := p.FindAVPByCode(16777217, 621, 10415); err != nil || got != registered {
		t.Fatalf("Sh registration lost after loading its ancestor: %v, %v", got, err)
	}
	loaded, err := p.FindAVP(16777216, uint32(621))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := p.FindAVP(16777217, uint32(621)); err != nil || got != loaded || got == registered {
		t.Errorf("code-only lookup = %v, %v; want loaded Cx code-only AVP, independent of Sh registration", got, err)
	}
	if got, err := before.FindAVP(16777217, uint32(621)); err != nil || got != originalBare {
		t.Errorf("earlier Snapshot changed after loading Cx: %v, %v", got, err)
	}
	if _, err := p.App(16777217); !errors.Is(err, ErrApplicationUnsupported) {
		t.Errorf("registration must not declare Sh: %v", err)
	}
	assertNoWildcardRegistrations(t, p.Snapshot())
}

func TestCxShScopeAfterIdenticalRegistrationThenLoad(t *testing.T) {
	definition, err := New(Base, NASREQ, Cx).FindAVPByCode(16777216, 621, 10415)
	if err != nil {
		t.Fatal(err)
	}
	cx, err := bundledFS.ReadFile("bundled/" + string(Cx))
	if err != nil {
		t.Fatal(err)
	}
	for _, app := range []uint32{16777216, 16777217} {
		p := New(Base, NASREQ)
		mustRegister(t, p, app, definition)
		registered, err := p.FindAVPByCode(app, 621, 10415)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Load(bytes.NewReader(cx)); err != nil {
			t.Fatal(err)
		}
		// The loaded Cx definition supplies the code-only lookup, while the
		// registered object itself stays explicitly vendor scoped.
		got, err := p.FindAVP(app, uint32(621))
		want, wantErr := p.FindAVP(16777216, uint32(621))
		if err != nil || wantErr != nil || got == registered || got != want {
			t.Errorf("app %d code-only 621 after identical registration/load = %v, %v; want Cx code-only definition %v, %v", app, got, err, want, wantErr)
		}
		if explicit, err := p.FindAVPByCode(app, 621, 10415); err != nil || explicit != registered {
			t.Errorf("app %d explicit registered definition changed: %v, %v", app, explicit, err)
		}
		assertNoWildcardRegistrations(t, p.Snapshot())
	}
}

package dict

import (
	"fmt"
	"testing"
)

// The decoder resolves every AVP with FindAVP, so these measure the
// per-AVP dictionary cost on the decode path.

func BenchmarkFindAVP(b *testing.B) {
	for b.Loop() {
		if _, err := Default.FindAVP(4, 461, 0); err != nil { // Service-Context-Id
			b.Fatal(err)
		}
	}
}

func BenchmarkFindAVPInherited(b *testing.B) {
	for b.Loop() {
		if _, err := Default.FindAVP(16777238, 264, 0); err != nil { // Gx Origin-Host
			b.Fatal(err)
		}
	}
}

// BenchmarkFindAVPUndeclared resolves an AVP of application 4 for Gx
// with a dictionary that declares application 4 but not Gx.
func BenchmarkFindAVPUndeclared(b *testing.B) {
	p := New(Base, CreditControl, RoRf, NASREQ)
	for b.Loop() {
		_, _ = p.FindAVP(16777238, 461, 0) // Service-Context-Id
	}
}

// BenchmarkFindAVPMiss looks up an AVP no dictionary defines.
func BenchmarkFindAVPMiss(b *testing.B) {
	for b.Loop() {
		_, _ = Default.FindAVP(16777265, 99999, 99999) // SWx, deepest ancestor chain
	}
}

// BenchmarkRegisterAVP measures one change to a Parser holding every
// bundled dictionary: each change rebuilds the index.
func BenchmarkRegisterAVP(b *testing.B) {
	p := New(AllBundled()...)
	n := uint32(0)
	for b.Loop() {
		n++
		if err := p.RegisterAVP(4, &AVP{Name: fmt.Sprintf("Bench-%d", n), Code: 70000 + n, VendorID: 99999,
			Must: "V", Data: Data{TypeName: "UTF8String"}}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFindAVPParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Default.FindAVP(16777238, 264, 0); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

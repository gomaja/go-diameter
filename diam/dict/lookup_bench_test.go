package dict

import (
	"fmt"
	"testing"
)

// The decoder resolves every AVP with FindAVPByCode, so these measure the
// per-AVP dictionary cost on the decode path.

func BenchmarkFindAVPByCode(b *testing.B) {
	for b.Loop() {
		if _, err := Default.FindAVPByCode(4, 461, 0); err != nil { // Service-Context-Id
			b.Fatal(err)
		}
	}
}

func BenchmarkFindAVPByCodeInherited(b *testing.B) {
	for b.Loop() {
		if _, err := Default.FindAVPByCode(16777238, 264, 0); err != nil { // Gx Origin-Host
			b.Fatal(err)
		}
	}
}

// BenchmarkFindAVPByCodeUndeclared resolves an AVP of application 4 for Gx
// with a dictionary that declares application 4 but not Gx.
func BenchmarkFindAVPByCodeUndeclared(b *testing.B) {
	p := New(Base, CreditControl, RoRf, NASREQ)
	for b.Loop() {
		_, _ = p.FindAVPByCode(16777238, 461, 0) // Service-Context-Id
	}
}

// BenchmarkFindAVPByCodeMiss looks up an AVP no dictionary defines.
func BenchmarkFindAVPByCodeMiss(b *testing.B) {
	for b.Loop() {
		_, _ = Default.FindAVPByCode(16777265, 99999, 99999) // SWx, deepest ancestor chain
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

func BenchmarkFindAVPByCodeParallel(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Default.FindAVPByCode(16777238, 264, 0); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

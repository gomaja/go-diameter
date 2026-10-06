package dict

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestLoadAppliesAllOrNothing(t *testing.T) {
	p := New(Base)
	for name, xml := range map[string]string{
		"unsupported type": `<diameter><application id="4" type="auth" name="Test">
			<avp name="Test-Good" code="70000" vendor-id="99999"><data type="UTF8String"/></avp>
			<avp name="Test-Bad" code="70001" vendor-id="99999"><data type="NoSuchType"/></avp>
		</application></diameter>`,
		"command loaded twice": `<diameter><application id="0">
			<avp name="Test-Good" code="70000" vendor-id="99999"><data type="UTF8String"/></avp>
			<command code="257" short="CE" name="Capabilities-Exchange"/>
		</application></diameter>`,
		"malformed XML": `<diameter><application id="4"><avp name="Test-Good" code="70000"`,
	} {
		t.Run(name, func(t *testing.T) {
			before := p.Snapshot()
			if err := p.Load(strings.NewReader(xml)); err == nil {
				t.Fatal("Load succeeded")
			}
			requireUnchanged(t, p, before)
			if _, err := p.App(4); err == nil {
				t.Error("application 4 declared by a failed Load")
			}
		})
	}
	if _, err := NewParser("bundled/base.xml", "no-such-file.xml"); err == nil {
		t.Error("NewParser succeeded with a missing file")
	}
}

func TestSnapshotIsUnchangedByLaterChanges(t *testing.T) {
	p := New(Base)
	old := p.Snapshot()
	oldDump := dumpSnapshot(old)
	if err := p.Load(strings.NewReader(`<diameter><application id="4" type="auth" name="Test">
		<avp name="Test-Loaded" code="70000" must="V" vendor-id="99999"><data type="UTF8String"/></avp>
	</application></diameter>`)); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, p, 4, vendorAVP("Test-Registered", 70001, "UTF8String"))
	p.SetStrict(false)
	p.SetMaxGroupedDepth(3)

	diffDumps(t, "old snapshot", dumpSnapshot(old), oldDump)
	for _, code := range []uint32{70000, 70001} {
		if _, err := old.FindAVPByCode(4, code, testVendor); err == nil {
			t.Errorf("old snapshot resolves code %d", code)
		}
		if _, err := p.FindAVPByCode(4, code, testVendor); err != nil {
			t.Errorf("current snapshot: %v", err)
		}
	}
	if !old.Strict() || old.MaxGroupedDepth() != DefaultMaxGroupedDepth {
		t.Errorf("old policy: strict %t, depth %d", old.Strict(), old.MaxGroupedDepth())
	}
	if p.Strict() || p.MaxGroupedDepth() != 3 {
		t.Errorf("new policy: strict %t, depth %d", p.Strict(), p.MaxGroupedDepth())
	}
}

func TestPolicySetters(t *testing.T) {
	p := New(Base)
	before := p.Snapshot()
	p.SetStrict(true)
	p.SetMaxGroupedDepth(0)
	requireUnchanged(t, p, before) // the values in effect publish nothing
	for _, tc := range []struct{ set, want int }{{40, 40}, {1, 1}, {0, DefaultMaxGroupedDepth}, {-5, DefaultMaxGroupedDepth}} {
		p.SetMaxGroupedDepth(tc.set)
		if have := p.MaxGroupedDepth(); have != tc.want {
			t.Errorf("SetMaxGroupedDepth(%d): MaxGroupedDepth() = %d, want %d", tc.set, have, tc.want)
		}
	}
	p.SetStrict(false)
	if p.Strict() {
		t.Error("SetStrict(false) left the Parser strict")
	}
	// Policy changes keep the definitions.
	diffDumps(t, "after policy changes", dumpSnapshot(p.Snapshot()), dumpSnapshot(before))
}

// TestStringLeavesRulesUnchanged guards the shared rules: String printed
// the effective minimum of required rules by writing it into them.
func TestStringLeavesRulesUnchanged(t *testing.T) {
	p := New(Base)
	cmd, err := p.FindCommand(0, 257)
	if err != nil {
		t.Fatal(err)
	}
	var rule *Rule
	for _, r := range cmd.Request.Rule {
		if r.Required && r.Min == 0 {
			rule = r
			break
		}
	}
	if rule == nil {
		t.Fatal("CER has no required rule without a minimum")
	}
	if s := p.String(); !strings.Contains(s, "Capabilities-Exchange-Request") {
		t.Fatalf("String() = %.200s", s)
	}
	if rule.Min != 0 {
		t.Errorf("String() set %s's minimum to %d", rule.AVP, rule.Min)
	}
}

// TestLookupsWhileChanging runs every lookup against a Parser that loads
// and registers definitions meanwhile. Run with -race.
func TestLookupsWhileChanging(t *testing.T) {
	p := New(Base, CreditControl, RoRf, NASREQ, Gx)
	const changes = 20
	var wg sync.WaitGroup
	done := make(chan struct{})
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				_, _ = p.FindAVPByCode(gxAppID, 70000, testVendor)
				_, _ = p.FindAVPWithVendor(gxAppID, "Test-Changing-0", testVendor)
				_, _ = p.FindAVP(gxAppID, "Session-Id")
				_, _ = p.FindCommand(gxAppID, 272)
				_, _ = p.App(4)
				_ = p.Apps()
				_, _ = p.Enum(0, 274, 1)
				_, _ = p.Rule(0, 284, "Proxy-Host")
				_, _ = p.ScanAVP("Session-Id")
				_ = p.Strict()
				_ = p.MaxGroupedDepth()
			}
		}()
	}
	for i := range changes {
		var err error
		if i%2 == 0 {
			err = p.RegisterAVP(4, vendorAVP(fmt.Sprintf("Test-Changing-%d", i), 70000+uint32(i), "UTF8String"))
		} else {
			err = p.Load(strings.NewReader(fmt.Sprintf(`<diameter><application id="4" type="auth" name="Test">
				<avp name="Test-Changing-%d" code="%d" must="V" vendor-id="99999"><data type="Unsigned32"/></avp>
			</application></diameter>`, i, 70000+i)))
		}
		if err != nil {
			t.Error(err)
		}
		p.SetStrict(i%2 == 0)
	}
	close(done)
	wg.Wait()
	for i := range changes {
		if _, err := p.FindAVPByCode(gxAppID, 70000+uint32(i), testVendor); err != nil {
			t.Error(err)
		}
	}
}

package base_test

import (
	"testing"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type privatePayload []byte

func (p privatePayload) Serialize() []byte     { return p }
func (p privatePayload) Len() int              { return len(p) }
func (p privatePayload) Padding() int          { return 0 }
func (p privatePayload) Type() datatype.TypeID { return 123456789 }
func (p privatePayload) String() string        { return "private" }

func TestCloneAVPRetainsUnregisteredPayloadWithoutAliasing(t *testing.T) {
	payload := privatePayload{1, 2, 3}
	original := diam.NewAVP(9999, 0, 0, payload)
	copy := base.CloneAVP(original)
	got, ok := copy.Data.(datatype.Unknown)
	if !ok || len(got) != 3 {
		t.Fatalf("clone data = %T %v", copy.Data, copy.Data)
	}
	got[0] = 9
	if payload[0] != 1 {
		t.Fatal("clone retained caller storage")
	}
}

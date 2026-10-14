package dict

import (
	"slices"
	"testing"
)

// An implicit dictionary must not advertise applications the program did not select.
func TestDefaultStartsWithBase(t *testing.T) {
	var applications []uint32
	for _, app := range Default.Apps() {
		applications = append(applications, app.ID)
	}
	if !slices.Equal(applications, []uint32{0, 3}) {
		t.Fatalf("implicit applications = %v; want base 0 and 3", applications)
	}
}

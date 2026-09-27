package base

import (
	"fmt"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
)

// CloneAVP copies an AVP and its data, including nested Grouped AVPs.
func CloneAVP(a *diam.AVP) *diam.AVP {
	if a == nil {
		return nil
	}
	copy := *a
	if a.Data == nil {
		return &copy
	}
	if grouped, ok := a.Data.(*diam.GroupedAVP); ok {
		if grouped == nil {
			copy.Data = (*diam.GroupedAVP)(nil)
		} else {
			copy.Data = &diam.GroupedAVP{AVP: CloneAVPs(grouped.AVP)}
		}
		return &copy
	}
	// Diameter datatype decoders allocate their own data. This also copies
	// custom registered types instead of retaining caller-owned storage.
	data, err := datatype.Decode(a.Data.Type(), a.Data.Serialize())
	if err != nil {
		panic(fmt.Sprintf("clone Diameter AVP %d: %v", a.Code, err))
	}
	copy.Data = data
	return &copy
}

// CloneAVPs copies a slice and every AVP reachable through it.
func CloneAVPs(avps []*diam.AVP) []*diam.AVP {
	if avps == nil {
		return nil
	}
	copy := make([]*diam.AVP, len(avps))
	for i, a := range avps {
		copy[i] = CloneAVP(a)
	}
	return copy
}

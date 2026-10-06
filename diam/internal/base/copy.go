package base

import (
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
	switch data := a.Data.(type) {
	case datatype.Address:
		copy.Data = data.Clone()
		return &copy
	case *datatype.Address:
		if data != nil {
			cloned := data.Clone()
			copy.Data = &cloned
		}
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
	// Built-in datatype decoders allocate their own data. Registered custom
	// decoders receive a copied byte slice; unregistered types keep those bytes.
	raw := append([]byte(nil), a.Data.Serialize()...)
	data, err := datatype.Decode(a.Data.Type(), raw)
	if err != nil {
		copy.Data = datatype.Unknown(raw)
		return &copy
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

// CloneAddresses copies a slice and each address value.
func CloneAddresses(addresses []datatype.Address) []datatype.Address {
	if addresses == nil {
		return nil
	}
	cloned := make([]datatype.Address, len(addresses))
	for i, address := range addresses {
		cloned[i] = address.Clone()
	}
	return cloned
}

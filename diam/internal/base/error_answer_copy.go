package base

import (
	"strings"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// rebuildAnswerAVP preserves a received value while applying RFC 6733 §4.1's
// sending rules at every level. Receive-side tolerance of M and reserved bits
// must not prevent the answers required by §§6.2 and 7 from being sent.
func rebuildAnswerAVP(received *diam.AVP, appID uint32, dictionary *dict.Parser, definitions *dict.Snapshot, depth int) *diam.AVP {
	if received == nil || received.Data == nil {
		return nil
	}
	flags := received.Flags & avp.Mbit
	definition, err := definitions.FindAVPByCode(appID, received.Code, received.VendorID)
	if err == nil {
		if _, raw := received.Data.(datatype.Unknown); raw {
			// Undecoded known values cannot be reused as ordinary answer fields.
			return nil
		}
		flags = 0
		if strings.Contains(definition.Must, "M") {
			flags |= avp.Mbit
		}
		if strings.Contains(definition.Must, "P") {
			flags |= avp.Pbit
		}
	}
	if received.VendorID != 0 {
		flags |= avp.Vbit
	}
	data := received.Data
	// RFC 6733 §7.5: Failed-AVP descendants are evidence, including their flags.
	if received.Code == avp.FailedAVP && received.VendorID == 0 {
		if !answerEvidenceFits(received, depth, definitions.MaxGroupedDepth()) {
			return nil
		}
	} else {
		var group *diam.GroupedAVP
		switch value := data.(type) {
		case *diam.GroupedAVP:
			group = value
			if group == nil {
				return nil
			}
		case datatype.Grouped:
			group, err = diam.DecodeGrouped(value, appID, dictionary)
			if err != nil {
				return nil
			}
		}
		if group != nil {
			if depth >= definitions.MaxGroupedDepth() {
				return nil
			}
			copied := &diam.GroupedAVP{AVP: make([]*diam.AVP, 0, len(group.AVP))}
			for _, child := range group.AVP {
				rebuilt := rebuildAnswerAVP(child, appID, dictionary, definitions, depth+1)
				if rebuilt == nil {
					return nil
				}
				copied.AVP = append(copied.AVP, rebuilt)
			}
			data = copied
		}
	}
	return diam.NewAVP(received.Code, flags, received.VendorID, data)
}

// Check evidence without changing its flags or interpreting its payload.
func answerEvidenceFits(a *diam.AVP, depth, limit int) bool {
	if a == nil || a.Data == nil {
		return false
	}
	if group, ok := a.Data.(*diam.GroupedAVP); ok {
		if group == nil || depth >= limit {
			return false
		}
		for _, child := range group.AVP {
			if !answerEvidenceFits(child, depth+1, limit) {
				return false
			}
		}
	}
	return true
}

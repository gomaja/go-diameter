package diam

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/internal/validation"
)

// ValidationError is the first dictionary grammar violation in a message.
// FailedAVP is the offending AVP or a zero-filled example of a missing AVP.
// A nested failure retains its Grouped AVP hierarchy.
type ValidationError struct {
	ResultCode uint32
	FailedAVP  *AVP
	Reason     string
}

func (e *ValidationError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("Diameter validation failed (%d): %s", e.ResultCode, e.Reason)
}

type validationKey struct{ code, vendor uint32 }
type validationRule struct {
	rule       *dict.Rule
	definition *dict.AVP
}

// RFC 6733 §7.2: optional Session-Id occupies the fixed prefix.
var genericErrorRules = []*dict.Rule{
	{AVP: "Session-Id", Max: 1, MaxSet: true, Fixed: true},
	{AVP: "Origin-Host", Required: true, Max: 1, MaxSet: true},
	{AVP: "Origin-Realm", Required: true, Max: 1, MaxSet: true},
	{AVP: "Result-Code", Required: true, Max: 1, MaxSet: true},
	{AVP: "Origin-State-Id", Max: 1, MaxSet: true},
	{AVP: "Error-Message", Max: 1, MaxSet: true},
	{AVP: "Error-Reporting-Host", Max: 1, MaxSet: true},
	{AVP: "Failed-AVP", Max: 1, MaxSet: true},
	{AVP: "Experimental-Result", Max: 1, MaxSet: true},
	{AVP: "Proxy-Info"},
	{AVP: "AVP"},
}

// Validate checks the message against its request or answer command grammar
// and each known Grouped AVP grammar. It does not mutate the message.
// RFC 6733 §§3.1-3.2, 4.1, 4.4-4.5, 7.1 and 7.5 define these checks.
// Receive validation is opt-in and enforces §3.2 fixed positions; §8.8
// describes first-position Session-Id as SHOULD for senders.
// Use ValidateOutgoing for locally built messages;
// Validate does not enforce dictionary M/P sending rules on understood AVPs.
// The whole message is checked against one dict.Snapshot of its dictionary.
func (m *Message) Validate() *ValidationError {
	return m.validate(false)
}

// ValidateOutgoing checks the message grammar and outgoing flag rules against
// one dictionary snapshot. RFC 6733 §§3, 4.1 and 4.5 require senders to clear
// reserved bits and follow the application's AVP flag definitions. Unknown
// AVPs have no dictionary M/P rules to check. Per §7.5, Failed-AVP contents
// retain the offending flags as evidence; only their container is checked.
// Proxy-Info copied by Answer is a peer echo under §6.2. Answer clears its
// reserved bits (§4.1), retaining all other flags and contents. Newly added
// Proxy-Info remains subject to sending rules.
func (m *Message) ValidateOutgoing() *ValidationError {
	return m.validate(true)
}

// errorAnswerOption is inaccessible to callers outside the Diameter tree.
// The internal builder alone can authorize omission under RFC 6733 §6.2.
type errorAnswerOption = validation.ErrorAnswer

// ValidateErrorAnswer is the internal builder bridge. Its option can only be
// constructed by the internal validation package; its zero value is strict.
// Public callers use ValidateOutgoing, which never relaxes Session-Id presence.
func (m *Message) ValidateErrorAnswer(option errorAnswerOption) *ValidationError {
	return m.validate(true, option)
}

func (m *Message) validate(outgoing bool, options ...errorAnswerOption) *ValidationError {
	if m == nil || m.Header == nil {
		return &ValidationError{ResultCode: InvalidHDRBits, Reason: "missing Diameter header"}
	}
	dictionary := m.Dictionary().Snapshot()
	h := m.Header
	// RFC 6733 §3: reserved command bits are zero on send and ignored on
	// receipt. The defined R/E and R/T combinations remain constrained.
	if outgoing && h.CommandFlags&0x0f != 0 || h.CommandFlags&RequestFlag != 0 && h.CommandFlags&ErrorFlag != 0 || h.CommandFlags&RequestFlag == 0 && h.CommandFlags&RetransmittedFlag != 0 {
		return &ValidationError{ResultCode: InvalidHDRBits, Reason: "invalid command header flags"}
	}
	var echoes map[*AVP][]byte
	if outgoing && h.CommandFlags&RequestFlag == 0 {
		echoes = m.echoedProxyInfo
	}
	if outgoing {
		if err := walkOutgoingFlags(m.AVP, h.ApplicationID, dictionary, make(map[*GroupedAVP]bool), outgoingCommandRules(h, dictionary), echoes); err != nil {
			return err
		}
	}
	// RFC 6733 §7.2: E-bit answers use the generic error grammar, not the
	// application-specific answer CCF. Only protocol errors use E here.
	if h.CommandFlags&ErrorFlag != 0 {
		var code uint32
		for _, a := range m.AVP {
			if a != nil && a.Code == avp.ResultCode && a.VendorID == 0 {
				if v, ok := a.Data.(datatype.Unsigned32); ok {
					code = uint32(v)
				}
				break
			}
		}
		if code < 3000 || code >= 4000 {
			return &ValidationError{ResultCode: InvalidHDRBits, Reason: "E bit requires a 3xxx result code"}
		}
		return validateAVPs(m.AVP, genericErrorRules, h.ApplicationID, dictionary, echoes)
	}
	command, err := dictionary.FindCommand(h.ApplicationID, h.CommandCode)
	if err != nil {
		return &ValidationError{ResultCode: CommandUnsupported, Reason: err.Error()}
	}
	grammar := &command.Answer
	if h.CommandFlags&RequestFlag != 0 {
		grammar = &command.Request
	}
	if len(grammar.Rule) == 0 {
		return &ValidationError{ResultCode: InvalidHDRBits, Reason: "R bit selects an undefined command grammar"}
	}
	if grammar.Proxiable != nil && (h.CommandFlags&ProxiableFlag != 0) != *grammar.Proxiable {
		return &ValidationError{ResultCode: InvalidHDRBits, Reason: "P bit disagrees with command grammar"}
	}
	rules := grammar.Rule
	// RFC 6733 §6.2 applies to errors too: a request without Session-Id
	// still receives an answer. Error answers may therefore omit it,
	// independently of Failed-AVP (§7.1.5: SHOULD). Only presence/minimum
	// is relaxed; fixed placement, maximum and every other rule remain.
	// On send, only the internal builder can authorize this exception after
	// checking the request. Ordinary ValidateOutgoing calls remain strict.
	allowMissingSession := !outgoing
	for _, option := range options {
		allowMissingSession = allowMissingSession || option.MissingSessionID()
	}
	if allowMissingSession && h.CommandFlags&RequestFlag == 0 && errorAnswer(m.AVP) {
		rules = append([]*dict.Rule(nil), rules...)
		for i, rule := range rules {
			if rule.AVP == "Session-Id" {
				optional := *rule
				optional.Required, optional.Min = false, 0
				rules[i] = &optional
			}
		}
	}
	return validateAVPs(m.AVP, rules, h.ApplicationID, dictionary, echoes)
}

// RFC 6733 §7.1: 3xxx, 4xxx and 5xxx are error classes. Informational
// and success answers retain all mandatory command members.
func errorAnswer(items []*AVP) bool {
	for _, a := range items {
		if a != nil && a.Code == avp.ResultCode && a.VendorID == 0 {
			if result, ok := a.Data.(datatype.Unsigned32); ok {
				return result >= 3000 && result < 6000
			}
			return false
		}
	}
	return false
}

// RFC 6733 §7.5 requires 1* { AVP }, but the members are peer evidence:
// unknown AVPs, invalid flags and incomplete grouped ancestry must survive.
// Enforce the container's nonempty shape without validating its contents.
func validateFailedEvidence(a *AVP) *ValidationError {
	g, ok := a.Data.(*GroupedAVP)
	if !ok || g == nil {
		return &ValidationError{ResultCode: InvalidAVPValue, FailedAVP: a, Reason: "Failed-AVP must contain grouped evidence"}
	}
	if len(g.AVP) == 0 {
		return &ValidationError{ResultCode: MissingAVP, FailedAVP: a, Reason: "Failed-AVP requires at least one evidence AVP"}
	}
	for _, member := range g.AVP {
		if member == nil {
			return &ValidationError{ResultCode: InvalidAVPValue, FailedAVP: a, Reason: "nil Failed-AVP evidence"}
		}
	}
	return nil
}

func validateAVPs(items []*AVP, rules []*dict.Rule, appID uint32, dictionary *dict.Snapshot, echoes ...map[*AVP][]byte) *ValidationError {
	byKey := make(map[validationKey]validationRule, len(rules))
	ordered := make([]validationRule, 0, len(rules))
	var wildcard *dict.Rule
	for _, rule := range rules {
		if rule.AVP == "AVP" {
			wildcard = rule
			continue
		}
		definition, err := dictionary.FindAVPByName(appID, rule.AVP)
		if err != nil {
			continue
		} // An incomplete dictionary cannot identify this rule's AVP.
		entry := validationRule{rule, definition}
		byKey[validationKey{definition.Code, definition.VendorID}] = entry
		ordered = append(ordered, entry)
	}
	// RFC 6733 §7.1.5 distinguishes an absent required AVP (5005) from
	// an AVP present outside its fixed position (§3.2, 5008). Count first
	// so an absent fixed member is not mistaken for an ordering violation.
	present := make(map[validationKey]int, len(ordered))
	for _, a := range items {
		if a != nil {
			present[validationKey{a.Code, a.VendorID}]++
		}
	}
	for _, entry := range ordered {
		key := validationKey{entry.definition.Code, entry.definition.VendorID}
		if entry.rule.Fixed && present[key] < minimumCount(entry.rule) {
			return &ValidationError{ResultCode: MissingAVP, FailedAVP: missingAVPExample(entry.definition, appID, dictionary, make(map[validationKey]bool)), Reason: "required fixed AVP missing"}
		}
	}
	counts := make(map[validationKey]int, len(ordered))
	extensionCount, extensionMinimumCount := 0, 0
	fixedIndex, fixedClosed := 0, false
	for i, a := range items {
		if a == nil {
			return &ValidationError{ResultCode: AVPNotAllowed, Reason: fmt.Sprintf("nil AVP at position %d", i)}
		}
		key := validationKey{a.Code, a.VendorID}
		entry, listed := byKey[key]
		definition, known := dictionary.FindAVP(appID, a.Code, a.VendorID)
		if known == nil && !isEchoedProxy(a, echoes) {
			if invalidAVPFlags(a.Flags, definition) {
				return &ValidationError{ResultCode: InvalidAVPBits, FailedAVP: a, Reason: "AVP flags disagree with dictionary"}
			}
		}
		// RFC 6733 §7.1.5: 5008 is for an AVP that MUST NOT be present, which
		// only a known AVP can be judged. An AVP the dictionary does not know
		// is left to §4.1: ignored when M is clear, or answered with 5001 by the
		// separate unknown-mandatory check. Rejecting it here would also turn
		// every gap in an incomplete dictionary into a false 5008.
		if !listed && wildcard == nil && known == nil {
			return &ValidationError{ResultCode: AVPNotAllowed, FailedAVP: a, Reason: "AVP not in grammar"}
		}
		// RFC 6733 §3.2 calls a wildcard any arbitrary AVP: unknown
		// AVPs satisfy its minimum too. Maxima count known AVPs only,
		// so an unknown optional AVP never causes rejection (§4.1).
		if !listed && wildcard != nil {
			extensionMinimumCount++
		}
		// Unknown AVPs do not occupy a fixed position or close its prefix.
		// Mandatory unknowns remain the separate §4.1 check's concern.
		if !listed && known != nil {
			continue
		}
		if !listed && wildcard != nil && known == nil {
			extensionCount++
			if hasMaximum(wildcard) && extensionCount > wildcard.Max {
				code := uint32(AVPOccursTooManyTimes)
				if wildcard.Max == 0 {
					code = AVPNotAllowed
				}
				return &ValidationError{ResultCode: code, FailedAVP: a, Reason: "extension AVP exceeds maximum occurrences"}
			}
		}
		if listed && entry.rule.Fixed {
			max := 1
			if hasMaximum(entry.rule) {
				max = entry.rule.Max
			}
			if counts[key] >= max {
				code := uint32(AVPOccursTooManyTimes)
				if max == 0 {
					code = AVPNotAllowed
				}
				return &ValidationError{ResultCode: code, FailedAVP: a, Reason: "fixed AVP exceeds maximum occurrences"}
			}
			// RFC 6733 §7.1.5: report the first excess instance as 5009
			// even when it follows the fixed prefix. A single misplaced
			// instance still violates §3.2 and receives 5008.
			if fixedClosed {
				return &ValidationError{ResultCode: AVPNotAllowed, FailedAVP: a, Reason: "fixed AVP appears after the prefix"}
			}
			for fixedIndex < len(ordered) {
				candidate := ordered[fixedIndex]
				if !candidate.rule.Fixed {
					fixedIndex++
					continue
				}
				candidateKey := validationKey{candidate.definition.Code, candidate.definition.VendorID}
				if candidateKey == key {
					break
				}
				if counts[candidateKey] < minimumCount(candidate.rule) {
					return &ValidationError{ResultCode: AVPNotAllowed, FailedAVP: a, Reason: "fixed AVP out of order"}
				}
				fixedIndex++
			}
			if fixedIndex >= len(ordered) || ordered[fixedIndex].definition.Code != a.Code || ordered[fixedIndex].definition.VendorID != a.VendorID {
				return &ValidationError{ResultCode: AVPNotAllowed, FailedAVP: a, Reason: "fixed AVP out of order"}
			}
			if counts[key]+1 >= max {
				fixedIndex++
			}
		} else {
			fixedClosed = true
		}
		counts[key]++
		if listed && hasMaximum(entry.rule) && counts[key] > entry.rule.Max {
			code := uint32(AVPOccursTooManyTimes)
			if entry.rule.Max == 0 {
				code = AVPNotAllowed
			}
			return &ValidationError{ResultCode: code, FailedAVP: a, Reason: "AVP exceeds maximum occurrences"}
		}
		// RFC 6733 §6.2 requires the peer's complete Proxy-Info echo,
		// even when its members violate a grammar. Cardinality above still applies.
		if isEchoedProxy(a, echoes) {
			continue
		}
		if a.Code == avp.FailedAVP && a.VendorID == 0 {
			if err := validateFailedEvidence(a); err != nil {
				return err
			}
			continue
		}
		if known == nil && definition.Data.Type == datatype.GroupedType && len(definition.Data.Rule) > 0 {
			if _, ok := a.Data.(*GroupedAVP); ok {
				if childErr := validateAVPs(members(a), definition.Data.Rule, appID, dictionary); childErr != nil {
					example := &GroupedAVP{}
					if childErr.FailedAVP != nil {
						example.AVP = []*AVP{childErr.FailedAVP}
					}
					childErr.FailedAVP = newAVPWithFlags(a.Code, a.Flags, a.VendorID, example)
					return childErr
				}
				if definition.Code == avp.VendorSpecificApplicationID && definition.VendorID == 0 {
					if choiceErr := validateVendorApplicationChoice(a, members(a)); choiceErr != nil {
						return choiceErr
					}
				}
			}
		}
	}
	for _, entry := range ordered {
		key := validationKey{entry.definition.Code, entry.definition.VendorID}
		if counts[key] < minimumCount(entry.rule) {
			failed := missingAVPExample(entry.definition, appID, dictionary, make(map[validationKey]bool))
			return &ValidationError{ResultCode: MissingAVP, FailedAVP: failed, Reason: "required AVP missing"}
		}
	}
	// RFC 6733 §3.2: a wildcard's minimum is independent of named AVPs.
	// No concrete missing code exists for a wildcard; a containing Grouped
	// AVP supplies the identifiable example when this error is propagated.
	// At top level no example exists, so 5005 omits Failed-AVP (§7.1.5 SHOULD).
	if wildcard != nil && extensionMinimumCount < minimumCount(wildcard) {
		return &ValidationError{ResultCode: MissingAVP, Reason: "required extension AVP missing"}
	}
	return nil
}

func hasMaximum(rule *dict.Rule) bool { return rule.MaxSet || rule.Max > 0 }

// RFC 6733 §§7.1.5 and 7.5 require the missing AVP's Vendor-Id and a
// zero-valued payload of the correct minimum length. Grouped examples keep
// required child structure so the recipient can identify the missing field.
func missingAVPExample(definition *dict.AVP, appID uint32, dictionary *dict.Snapshot, seen map[validationKey]bool) *AVP {
	flags := requiredFlags(definition)
	key := validationKey{definition.Code, definition.VendorID}
	switch definition.Data.Type {
	case datatype.AddressType:
		return NewAVP(key.code, flags, key.vendor, datatype.Unknown(make([]byte, minimumAVPPayloadLength(datatype.AddressType))))
	case datatype.GroupedType:
		group := &GroupedAVP{}
		if !seen[key] {
			seen[key] = true
			for _, rule := range definition.Data.Rule {
				if rule.AVP == "AVP" {
					continue
				}
				child, err := dictionary.FindAVPByName(appID, rule.AVP)
				if err != nil {
					continue
				}
				for n := 0; n < minimumCount(rule); n++ {
					group.AVP = append(group.AVP, missingAVPExample(child, appID, dictionary, seen))
				}
			}
			delete(seen, key)
		}
		return NewAVP(key.code, flags, key.vendor, group)
	default:
		return NewAVP(key.code, flags, key.vendor, datatype.Unknown(make([]byte, minimumAVPPayloadLength(definition.Data.Type))))
	}
}

// RFC 6733 §6.11 requires exactly one authentication or accounting
// application ID. The ordinary independent count rules cannot express XOR.
func validateVendorApplicationChoice(parent *AVP, children []*AVP) *ValidationError {
	var choices []*AVP
	for _, child := range children {
		if child != nil && child.VendorID == 0 && (child.Code == avp.AuthApplicationID || child.Code == avp.AcctApplicationID) {
			choices = append(choices, child)
		}
	}
	if len(choices) == 1 {
		return nil
	}
	code := uint32(MissingAVP)
	if len(choices) == 0 {
		choices = []*AVP{
			NewAVP(avp.AuthApplicationID, avp.Mbit, 0, datatype.Unknown(make([]byte, 4))),
			NewAVP(avp.AcctApplicationID, avp.Mbit, 0, datatype.Unknown(make([]byte, 4))),
		}
	} else {
		code = AVPOccursTooManyTimes
	}
	return &ValidationError{
		ResultCode: code,
		FailedAVP:  newAVPWithFlags(parent.Code, parent.Flags, parent.VendorID, &GroupedAVP{AVP: choices}),
		Reason:     "Vendor-Specific-Application-Id requires exactly one application ID",
	}
}

func minimumCount(rule *dict.Rule) int {
	if rule.Min > 0 {
		return rule.Min
	}
	if rule.Required {
		return 1
	}
	return 0
}

func requiredFlags(definition *dict.AVP) uint8 {
	var flags uint8
	if flagListed(definition.Must, "M") {
		flags |= avp.Mbit
	}
	if flagListed(definition.Must, "P") {
		flags |= avp.Pbit
	}
	if definition.VendorID != 0 || flagListed(definition.Must, "V") {
		flags |= avp.Vbit
	}
	return flags
}

func invalidAVPFlags(flags uint8, definition *dict.AVP) bool {
	// RFC 6733 §4.1: M requires understanding, not agreement with the
	// dictionary's sending rule. This AVP is known; unknown mandatory AVPs
	// are handled separately by UnknownMandatoryAVPs. See also 3GPP TS 29.272
	// V19.6.0, Tables 7.3.1/1 and 7.3.1/2, NOTE 2 (ignore understood M).
	// P is reserved for future security use (senders SHOULD clear it);
	// reserved R bits SHOULD be ignored on receipt. Neither P nor R is
	// rejected here.
	// RFC 6733 §§4.1-4.1.1: V changes the AVP's identity and header layout,
	// and a present Vendor-Id cannot be zero, so V must remain consistent.
	set := flags&avp.Vbit != 0
	return set != (definition.VendorID != 0)
}

func walkOutgoingFlags(items []*AVP, appID uint32, dictionary *dict.Snapshot, ancestors map[*GroupedAVP]bool, rules []*dict.Rule, echoes ...map[*AVP][]byte) *ValidationError {
	for _, a := range items {
		if a == nil {
			return &ValidationError{ResultCode: AVPNotAllowed, Reason: "nil outgoing AVP"}
		}
		// RFC 6733 §6.2: echoed Proxy-Info belongs to the peer, including
		// its header flags and descendants, except reserved bits cleared by Answer
		// under §4.1. Locally added AVPs remain strict.
		if isEchoedProxy(a, echoes) {
			continue
		}
		// RFC 6733 §§4.1-4.1.1 also govern unknown AVPs' reserved bits and
		// Vendor-Id presence. Only dictionary-specific M/P checks need lookup.
		invalid := a.Flags&0x1f != 0 || (a.Flags&avp.Vbit != 0) != (a.VendorID != 0)
		definition, lookupErr := dictionary.FindAVP(appID, a.Code, a.VendorID)
		if lookupErr == nil {
			for _, flag := range []struct {
				name string
				bit  uint8
			}{{"M", avp.Mbit}, {"P", avp.Pbit}} {
				set := a.Flags&flag.bit != 0
				invalid = invalid || set && flagListed(definition.MustNot, flag.name) || !set && flagListed(definition.Must, flag.name)
			}
		}
		// Member prohibitions are scoped to this occurrence, not the shared
		// AVP definition (RFC 8581 §7.4; TS 29.212 V20.0.0 Table 5.4.0.1).
		for _, rule := range rules {
			if rule.MustNot == "" {
				continue
			}
			if rule.AVP != "AVP" {
				member, err := dictionary.FindAVPByName(appID, rule.AVP)
				if err != nil || member.Code != a.Code || member.VendorID != a.VendorID {
					continue
				}
			}
			for _, flag := range []struct {
				name string
				bit  uint8
			}{{"M", avp.Mbit}, {"P", avp.Pbit}} {
				invalid = invalid || a.Flags&flag.bit != 0 && flagListed(rule.MustNot, flag.name)
			}
		}
		if invalid {
			return &ValidationError{ResultCode: InvalidAVPBits, FailedAVP: a, Reason: fmt.Sprintf("outgoing AVP %d/%d flags violate sending rules", a.Code, a.VendorID)}
		}
		// RFC 6733 §7.5: preserve erroneous AVPs, including Grouped ancestry,
		// inside the base Failed-AVP. A vendor's code 279 is a different AVP.
		if a.Code == avp.FailedAVP && a.VendorID == 0 {
			if err := validateFailedEvidence(a); err != nil {
				return err
			}
			continue
		}
		if group, ok := a.Data.(*GroupedAVP); ok {
			if group == nil {
				return &ValidationError{ResultCode: InvalidAVPValue, FailedAVP: a, Reason: "nil outgoing Grouped AVP"}
			}
			if ancestors[group] {
				return &ValidationError{ResultCode: InvalidAVPValue, FailedAVP: a, Reason: "cyclic outgoing Grouped AVP"}
			}
			ancestors[group] = true
			var memberRules []*dict.Rule
			if lookupErr == nil {
				memberRules = definition.Data.Rule
			}
			err := walkOutgoingFlags(group.AVP, appID, dictionary, ancestors, memberRules)
			delete(ancestors, group)
			if err != nil {
				if err.FailedAVP == nil {
					err.FailedAVP = a
				} else {
					// Do not measure a malformed child's payload while reporting it.
					parent := *a
					parent.Data = &GroupedAVP{AVP: []*AVP{err.FailedAVP}}
					err.FailedAVP = &parent
				}
				return err
			}
		}
	}
	return nil
}

// flagListed reports whether a dictionary flag rule such as "M,V" names flag.
// Rules are single-letter flags; the comma-separated form used by the bundled
// dictionaries and the compact form ("MV") that user dictionaries may use are
// both accepted, so a formatting choice never weakens validation.
func flagListed(list, flag string) bool {
	if flag != "M" && flag != "V" && flag != "P" {
		return false
	}
	found := false
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" || item == "-" {
			continue
		}
		for _, c := range item {
			if c != 'M' && c != 'V' && c != 'P' {
				return false
			}
			found = found || string(c) == flag
		}
	}
	return found
}

func outgoingCommandRules(h *Header, dictionary *dict.Snapshot) []*dict.Rule {
	if h.CommandFlags&ErrorFlag != 0 {
		return genericErrorRules
	}
	c, err := dictionary.FindCommand(h.ApplicationID, h.CommandCode)
	if err != nil {
		return nil
	}
	if h.CommandFlags&RequestFlag != 0 {
		return c.Request.Rule
	}
	return c.Answer.Rule
}

// isEchoedProxy reports whether a is a Proxy-Info that Answer copied from the
// request and that still has the bytes it was echoed with.
func isEchoedProxy(a *AVP, echoes []map[*AVP][]byte) bool {
	if a == nil || a.Code != avp.ProxyInfo || a.VendorID != 0 || len(echoes) == 0 {
		return false
	}
	echoed, ok := echoes[0][a]
	if !ok {
		return false
	}
	current, err := a.Serialize()
	return err == nil && bytes.Equal(current, echoed)
}

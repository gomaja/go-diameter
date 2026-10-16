package protocol

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

// HandshakeResult preserves semantic CEA processing separately from protocol
// observer metadata (RFC 6733 §§5.3.2,7). Adapters translate base parser error
// identities into their public error types without parsing the message again.
// A rejected or partially parsed CEA never becomes negotiated capabilities.
type HandshakeResult struct {
	err error
	cea *base.CEA
}

func newHandshakeResult(err error, cea *base.CEA) HandshakeResult {
	// Successful snapshots retain their own immutable CEA evidence too.
	c := newHandshakeErrorCopy()
	return HandshakeResult{err: c.copyError(err, 0), cea: c.copyCEA(cea)}
}

func (r HandshakeResult) Err() error { return copyHandshakeError(r.err) }
func (r HandshakeResult) CEA() *base.CEA {
	c := newHandshakeErrorCopy()
	return c.copyCEA(r.cea)
}

// Parser errors with mutable evidence are copied on capture and access. Plain
// sentinels retain identity; wrapped errors retain errors.Is/errors.As behavior.
func copyHandshakeError(err error, preserveFormatWrapper ...bool) error {
	if err == nil {
		return nil
	}
	c := newHandshakeErrorCopy()
	c.preserveFormatWrapper = len(preserveFormatWrapper) != 0 && preserveFormatWrapper[0]
	return c.copyError(err, 0)
}

func newHandshakeErrorCopy() handshakeErrorCopy {
	return handshakeErrorCopy{active: make(map[handshakeErrorVisit]bool), avps: make(map[*diam.AVP]*diam.AVP), ceas: make(map[*base.CEA]*base.CEA), remaining: 4096}
}

// Error children and exported metadata share one traversal. Starting a fresh
// traversal for an error-valued metadata field would let Self pointers and
// cyclic Unwrap methods bypass the bound. Cycles are cut, never reproduced:
// errors.Is, errors.As and Error must also terminate on the returned evidence.
type handshakeErrorCopy struct {
	active    map[handshakeErrorVisit]bool
	avps      map[*diam.AVP]*diam.AVP
	ceas      map[*base.CEA]*base.CEA
	remaining int
	cut       uint64
	// Standard formatting wrappers can retain their concrete diagnostic type
	// while the wrapped parser evidence remains detached and bounded.
	preserveFormatWrapper bool
}

type handshakeErrorVisit struct {
	typeOf reflect.Type
	ptr    uintptr
	length int
}

func (c *handshakeErrorCopy) enter(v reflect.Value, depth int) (func(), bool) {
	if depth > 64 || c.remaining == 0 {
		c.cut++
		return nil, false
	}
	c.remaining--
	var visit handshakeErrorVisit
	switch v.Kind() {
	case reflect.Pointer, reflect.Map:
		visit = handshakeErrorVisit{typeOf: v.Type(), ptr: v.Pointer()}
	case reflect.Slice:
		visit = handshakeErrorVisit{typeOf: v.Type(), ptr: v.Pointer(), length: v.Len()}
	default:
		return func() {}, true
	}
	if c.active[visit] {
		c.cut++
		return nil, false
	}
	c.active[visit] = true
	return func() { delete(c.active, visit) }, true
}

func (c *handshakeErrorCopy) copyError(err error, depth int) error {
	if err == nil {
		return nil
	}
	v := reflect.ValueOf(err)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return nil
		}
	}
	leave, ok := c.enter(v, depth)
	if !ok {
		return handshakeError{message: "handshake error cycle or traversal limit"}
	}
	defer leave()
	cut := c.cut
	message := func() string {
		// Calling the source Error method after a cyclic/deep edge was
		// found can itself overflow (for example a NumError wrapping itself).
		if c.cut != cut {
			return "handshake error cycle or traversal limit"
		}
		return err.Error()
	}
	switch e := err.(type) {
	case base.ErrFailedResultCode:
		return base.ErrFailedResultCode{CEA: c.copyCEA(e.CEA)}
	case *base.ErrFailedResultCode:
		return &base.ErrFailedResultCode{CEA: c.copyCEA(e.CEA)}
	case *base.ErrUnexpectedAVP:
		return &base.ErrUnexpectedAVP{AVP: c.copyAVP(e.AVP)}
	case *diam.MessageError:
		out := *e
		out.FailedAVP = c.copyAVP(e.FailedAVP)
		out.Err = c.copyError(e.Err, depth+1)
		return &out
	case *diam.ValidationError:
		out := *e
		out.FailedAVP = c.copyAVP(e.FailedAVP)
		return &out
	case interface{ Unwrap() []error }:
		if out, ok := c.copyTypedError(err, depth); ok {
			return out
		}
		causes := e.Unwrap()
		out := make([]error, len(causes))
		for i, cause := range causes {
			out[i] = c.copyError(cause, depth+1)
		}
		return handshakeErrors{message: message(), causes: out}
	case interface{ Unwrap() error }:
		if out, ok := c.copyTypedError(err, depth); ok {
			return out
		}
		cause := c.copyError(e.Unwrap(), depth+1)
		// fmt's single-cause wrapper has immutable text and one private error
		// field. Rebuild it around the bounded copy to retain its concrete
		// diagnostic type without retaining mutable parser evidence.
		if c.preserveFormatWrapper && v.Type() == handshakeFmtWrapType && c.cut == cut && cause != nil {
			before, after, found := strings.Cut(message(), e.Unwrap().Error())
			if found {
				return fmt.Errorf("%s%w%s", before, cause, after)
			}
		}
		return handshakeError{message: message(), cause: cause}
	default:
		// Standard immutable sentinels retain identity. Other leaf state,
		// including private scalar fields, needs wrapper-style isolation.
		if immutableHandshakeError(v) {
			return err
		}
		if out, ok := c.copyTypedError(err, depth); ok {
			return out
		}
		return handshakeError{message: message()}
	}
}

// Known parser evidence is a finite typed graph. Copy it iteratively so legal
// wire trees retain their full width and configured decoding depth without
// consuming the arbitrary error-metadata budget. Active cycles and repeated
// nonempty Grouped nodes use detached header evidence: preserving a shared DAG
// would let Error or Serialize expand exponentially even after a bounded copy.
func (c *handshakeErrorCopy) copyAVP(a *diam.AVP) *diam.AVP {
	out, descend := c.startAVP(a)
	if !descend {
		return out
	}
	type frame struct {
		source *diam.AVP
		out    *diam.AVP
		next   int
	}
	stack := []frame{{source: a, out: out}}
	for len(stack) != 0 {
		f := &stack[len(stack)-1]
		source := f.source.Data.(*diam.GroupedAVP)
		if f.next == len(source.AVP) {
			c.avps[f.source] = f.out
			delete(c.active, avpHandshakeVisit(f.source))
			stack = stack[:len(stack)-1]
			continue
		}
		child := source.AVP[f.next]
		copied, descend := c.startAVP(child)
		f.out.Data.(*diam.GroupedAVP).AVP[f.next] = copied
		f.next++
		if descend {
			stack = append(stack, frame{source: child, out: copied})
		}
	}
	return out
}

func avpHandshakeVisit(a *diam.AVP) handshakeErrorVisit {
	return handshakeErrorVisit{typeOf: reflect.TypeFor[*diam.AVP](), ptr: reflect.ValueOf(a).Pointer()}
}

func (c *handshakeErrorCopy) startAVP(a *diam.AVP) (*diam.AVP, bool) {
	if a == nil {
		return nil, false
	}
	prune := func() (*diam.AVP, bool) {
		c.cut++
		out := *a
		out.Data = datatype.Unknown(nil)
		return &out, false
	}
	if c.active[avpHandshakeVisit(a)] {
		return prune()
	}
	if out, ok := c.avps[a]; ok {
		if grouped, ok := out.Data.(*diam.GroupedAVP); ok && grouped != nil && len(grouped.AVP) != 0 {
			return prune()
		}
		// Scalar aliases have no recursive expansion. Give each occurrence
		// its own mutable payload, as separate decoded tree nodes have.
		return base.CloneAVP(out), false
	}
	if grouped, ok := a.Data.(*diam.GroupedAVP); ok && grouped != nil && len(grouped.AVP) != 0 {
		out := *a
		out.Data = &diam.GroupedAVP{AVP: make([]*diam.AVP, len(grouped.AVP))}
		c.active[avpHandshakeVisit(a)] = true
		return &out, true
	}
	out := base.CloneAVP(a)
	c.avps[a] = out
	return out, false
}

func (c *handshakeErrorCopy) copyAVPs(avps []*diam.AVP) []*diam.AVP {
	if avps == nil {
		return nil
	}
	out := make([]*diam.AVP, len(avps))
	for i, a := range avps {
		out[i] = c.copyAVP(a)
	}
	return out
}

func (c *handshakeErrorCopy) copyCEA(cea *base.CEA) *base.CEA {
	if cea == nil {
		return nil
	}
	if out, ok := c.ceas[cea]; ok {
		return out
	}
	out := &base.CEA{OriginHost: cea.OriginHost, OriginRealm: cea.OriginRealm, ResultCode: cea.ResultCode, OriginStateID: cea.OriginStateID, VendorID: cea.VendorID, ProductName: cea.ProductName, ErrorMessage: cea.ErrorMessage}
	visit := handshakeErrorVisit{typeOf: reflect.TypeFor[*base.CEA](), ptr: reflect.ValueOf(cea).Pointer()}
	if c.active[visit] {
		c.cut++
		return out
	}
	c.active[visit] = true
	defer delete(c.active, visit)
	out.HostIPAddresses = base.CloneAddresses(cea.HostIPAddresses)
	out.SupportedVendorID = c.copyAVPs(cea.SupportedVendorID)
	out.FailedAVP = c.copyAVPs(cea.FailedAVP)
	out.AcctApplicationID = c.copyAVPs(cea.AcctApplicationID)
	out.AuthApplicationID = c.copyAVPs(cea.AuthApplicationID)
	out.VendorSpecificApplicationID = c.copyAVPs(cea.VendorSpecificApplicationID)
	c.ceas[cea] = out
	return out
}

var handshakeSentinelType = reflect.TypeOf(errors.New(""))
var handshakeFmtWrapType = reflect.TypeOf(fmt.Errorf("%w", errors.New("")))

func immutableHandshakeError(v reflect.Value) bool {
	if v.Kind() != reflect.Pointer {
		return immutableHandshakeField(v.Type())
	}
	// A private scalar field can have an exported mutator. Preserve
	// only the standard immutable errors.New type and stateless pointers;
	// other safe scalar structs are copied with their concrete type intact.
	return v.Type() == handshakeSentinelType || v.Type().Elem().Size() == 0
}

// Wrappers and mutable leaves whose fields can be copied safely retain their
// concrete type and custom Is/As methods. Opaque private mutable state uses a
// detached tree instead; no unsafe access or source aliases are retained.
func (c *handshakeErrorCopy) copyTypedError(err error, depth int) (error, bool) {
	v := reflect.ValueOf(err)
	pointer := v.Kind() == reflect.Pointer
	if pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil, false
	}
	out, ok := c.copyStruct(v, depth+1)
	if !ok {
		return nil, false
	}
	if pointer {
		p := reflect.New(out.Type())
		p.Elem().Set(out)
		out = p
	}
	return out.Interface().(error), true
}

func (c *handshakeErrorCopy) copyStruct(v reflect.Value, depth int) (reflect.Value, bool) {
	if depth > 64 {
		c.cut++
		return reflect.Value{}, false
	}
	out := reflect.New(v.Type()).Elem()
	out.Set(v)
	for i := 0; i < v.NumField(); i++ {
		if v.Type().Field(i).PkgPath != "" {
			if !immutableHandshakeField(v.Field(i).Type()) {
				return reflect.Value{}, false
			}
			continue
		}
		field, ok := c.copyField(v.Field(i), depth+1)
		if !ok {
			return reflect.Value{}, false
		}
		out.Field(i).Set(field)
	}
	return out, true
}

func (c *handshakeErrorCopy) copyField(v reflect.Value, depth int) (reflect.Value, bool) {
	if depth > 64 {
		c.cut++
		return reflect.Value{}, false
	}
	if v.CanInterface() {
		// The standard reflect.Type descriptor is immutable. A custom Type
		// implementation can add mutable fields, so it still needs copying.
		if descriptor, ok := v.Interface().(reflect.Type); ok && reflect.TypeOf(descriptor) == reflect.TypeOf(reflect.TypeFor[int]()) {
			return v, true
		}
		switch evidence := v.Interface().(type) {
		case *diam.AVP:
			return reflect.ValueOf(c.copyAVP(evidence)), true
		case diam.AVP:
			return reflect.ValueOf(*c.copyAVP(&evidence)), true
		case *base.CEA:
			return reflect.ValueOf(c.copyCEA(evidence)), true
		case base.CEA:
			return reflect.ValueOf(*c.copyCEA(&evidence)), true
		}
		if err, ok := v.Interface().(error); ok {
			if copied := c.copyError(err, depth+1); copied != nil {
				out := reflect.ValueOf(copied)
				return out, out.Type().AssignableTo(v.Type())
			}
			return reflect.Zero(v.Type()), true
		}
	}
	leave, ok := c.enter(v, depth)
	if !ok {
		return reflect.Value{}, false
	}
	defer leave()
	switch v.Kind() {
	case reflect.Struct:
		return c.copyStruct(v, depth+1)
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type()), true
		}
		field, ok := c.copyField(v.Elem(), depth+1)
		if !ok {
			return reflect.Value{}, false
		}
		out := reflect.New(v.Type()).Elem()
		if v.Kind() == reflect.Pointer {
			out.Set(reflect.New(v.Type().Elem()))
			out.Elem().Set(field)
		} else {
			out.Set(field)
		}
		return out, true
	case reflect.Array, reflect.Slice:
		out := reflect.New(v.Type()).Elem()
		if v.Kind() == reflect.Slice {
			if v.IsNil() {
				return out, true
			}
			out.Set(reflect.MakeSlice(v.Type(), v.Len(), v.Len()))
		}
		for i := 0; i < v.Len(); i++ {
			field, ok := c.copyField(v.Index(i), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			out.Index(i).Set(field)
		}
		return out, true
	case reflect.Map:
		if !immutableHandshakeField(v.Type().Key()) {
			return reflect.Value{}, false
		}
		if v.IsNil() {
			return reflect.Zero(v.Type()), true
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for iter := v.MapRange(); iter.Next(); {
			field, ok := c.copyField(iter.Value(), depth+1)
			if !ok {
				return reflect.Value{}, false
			}
			out.SetMapIndex(iter.Key(), field)
		}
		return out, true
	default:
		return v, immutableHandshakeField(v.Type())
	}
}

func immutableHandshakeField(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Array:
		return immutableHandshakeField(t.Elem())
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if !immutableHandshakeField(t.Field(i).Type) {
				return false
			}
		}
		return true
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice, reflect.UnsafePointer:
		return false
	default:
		return true
	}
}

type handshakeError struct {
	message string
	cause   error
}

func (e handshakeError) Error() string { return e.message }
func (e handshakeError) Unwrap() error { return e.cause }

type handshakeErrors struct {
	message string
	causes  []error
}

func (e handshakeErrors) Error() string   { return e.message }
func (e handshakeErrors) Unwrap() []error { return e.causes }

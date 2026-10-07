// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// MessageBufferLength is the default buffer length for Diameter messages.
var MessageBufferLength = 1 << 10

const unknownCommandAVPCap = 32

var unknownCommand = &dict.Command{
	Name: "Unknown",
	Request: dict.CommandRule{
		Rule: make([]*dict.Rule, unknownCommandAVPCap),
	},
	Answer: dict.CommandRule{
		Rule: make([]*dict.Rule, unknownCommandAVPCap),
	},
}

// Message represents a Diameter message.
type Message struct {
	Header      *Header
	AVP         []*AVP // AVPs in this message.
	dispatchSeq uint64 // read order on a Server connection; zero outside Server dispatch

	DecodeErr            error // Possible decoding error on one or more AVPs (does not halt parsing)
	unknownMandatoryAVPs []*AVP
	dictionary           *dict.Parser // dictionary parser object used to encode and decode AVPs.
	stream               uint         // the stream this message was received on (if any)
	ctx                  context.Context
}

// DispatchSequence is the read order of a message dispatched by Server.
// It is zero for messages constructed or read outside Server.
func (m *Message) DispatchSequence() uint64 {
	if m == nil {
		return 0
	}
	return m.dispatchSeq
}

// UnknownMandatoryAVPs returns the unknown mandatory AVPs found during decode.
// For nested AVPs, each returned root retains only the Grouped hierarchy
// leading to offending AVPs. The returned slice is independent; AVPs are shared.
func (m *Message) UnknownMandatoryAVPs() []*AVP {
	return append([]*AVP(nil), m.unknownMandatoryAVPs...)
}

func unknownMandatoryHierarchy(a *AVP, appID uint32, dictionary *dict.Snapshot) *AVP {
	// RFC 6733 §4.1: an AVP is unsupported only on a dictionary miss.
	// Raw data from a known but undecodable AVP is not an unknown AVP.
	if a.Flags&avp.Mbit != 0 {
		if _, raw := a.Data.(datatype.Unknown); raw {
			if _, found := dictionary.AVP(appID, a.Code, a.VendorID); !found {
				return a
			}
		}
	}
	if _, ok := a.Data.(*GroupedAVP); !ok {
		return nil
	}
	var children []*AVP
	for _, child := range members(a) {
		if failed := unknownMandatoryHierarchy(child, appID, dictionary); failed != nil {
			children = append(children, failed)
		}
	}
	if len(children) == 0 {
		return nil
	}
	// RFC 6733 §7.5 permits the Failed-AVP to retain the Grouped hierarchy.
	return newAVPWithFlags(a.Code, a.Flags, a.VendorID, &GroupedAVP{AVP: children})
}

var readerBufferPool sync.Pool

func newReaderBuffer() *bytes.Buffer {
	if v := readerBufferPool.Get(); v != nil {
		return v.(*bytes.Buffer)
	}
	return bytes.NewBuffer(make([]byte, MessageBufferLength))
}

func putReaderBuffer(b *bytes.Buffer) {
	if cap(b.Bytes()) == MessageBufferLength {
		b.Reset()
		readerBufferPool.Put(b)
	}
}

func readerBufferSlice(buf *bytes.Buffer, l int) []byte {
	b := buf.Bytes()
	if l <= MessageBufferLength && cap(b) >= MessageBufferLength {
		return b[:l]
	}
	return make([]byte, l)
}

// ReadMessage reads a binary stream from the reader and uses the given
// dictionary to parse it. With a strict dictionary, recoverable AVP payload
// failures in requests return the decoded message and a non-fatal MessageError (5014 for
// invalid lengths, 5004 for invalid values; RFC 6733 §7.1.5). A non-strict
// dictionary leaves the failure in Message.DecodeErr and returns no error.
// Strict answers with payload failures outside Failed-AVP return Message.DecodeErr.
//
// The whole message, its command and every AVP, is decoded against the
// dict.Snapshot of dictionary current when ReadMessage starts, including its
// strictness, so a dictionary change made meanwhile applies to all of the
// message or to none of it. A nil dictionary means dict.Default.
func ReadMessage(reader io.Reader, dictionary *dict.Parser) (*Message, error) {
	buf := newReaderBuffer()
	// Safe to pool: the built-in datatype decoders copy their bytes, and an
	// AVP that fails to decode keeps a copy (fallbackData). A decoder
	// registered with datatype.RegisterDecoder must copy as well.
	defer putReaderBuffer(buf)
	snapshot := decodingSnapshot(dictionary)
	m := &Message{dictionary: dictionary}
	cmd, stream, err := m.readHeader(reader, buf, snapshot)
	m.stream = stream
	if err != nil {
		if m.Header == nil {
			return nil, err
		}
		return m, err
	}
	if err = m.readBody(reader, buf, cmd, stream, snapshot); err != nil {
		return m, err
	}
	if snapshot.Strict() && m.DecodeErr != nil {
		var decodeErr *avpDecodeError
		if m.Header.CommandFlags&RequestFlag != 0 && errors.As(m.DecodeErr, &decodeErr) {
			return m, &MessageError{
				ResultCode: decodeErr.resultCode,
				FailedAVP:  decodeErr.failedAVP,
				Err:        m.DecodeErr,
			}
		}
		return m, m.DecodeErr
	}
	return m, nil
}

// MessageStream returns the stream #, the message was received on (when applicable)
func (m *Message) MessageStream() uint {
	return m.stream
}

func (m *Message) readHeader(r io.Reader, buf *bytes.Buffer, dictionary *dict.Snapshot) (cmd *dict.Command, stream uint, err error) {
	b := buf.Bytes()[:HeaderLength]
	msr, isMulti := r.(MultistreamReader)
	if isMulti {
		_, stream, err = msr.ReadAtLeast(b, HeaderLength, InvalidStreamID)
		if err == nil {
			msr.SetCurrentStream(stream)
		}
	} else {
		_, err = io.ReadFull(r, b)
	}
	if err != nil {
		return nil, stream, err
	}
	m.Header = &Header{}
	err = m.Header.DecodeFromBytes(b)
	if err != nil {
		return nil, stream, err
	}
	cmd, err = dictionary.FindCommand(
		m.Header.ApplicationID,
		m.Header.CommandCode,
	)
	if err != nil {
		// Preserve messages for commands/applications not loaded in the
		// dictionary, so handlers can return RFC 6733 §7.1.3 protocol errors.
		cmd = unknownCommand
	}
	return cmd, stream, nil
}

func (m *Message) readBody(r io.Reader, buf *bytes.Buffer, cmd *dict.Command, stream uint, dictionary *dict.Snapshot) error {
	var err error
	var n int
	b := readerBufferSlice(buf, int(m.Header.MessageLength-HeaderLength))
	msr, isMulti := r.(MultistreamReader)
	if isMulti {
		n, _, err = msr.ReadAtLeast(b, len(b), stream)
	} else {
		n, err = io.ReadFull(r, b)
	}
	if err != nil {
		return fmt.Errorf("read body error: %v, %d bytes read", err, n)
	}
	n = m.maxAVPsFor(cmd)
	if n == 0 {
		// TODO: fail to load the dictionary instead.
		return fmt.Errorf(
			"command %s (%d) has no AVPs defined in the dictionary",
			cmd.Name, cmd.Code)
	}
	// Pre-allocate max # of AVPs for this message.
	m.AVP = make([]*AVP, 0, n)
	if err = m.decodeAVPs(b, dictionary); err != nil {
		return err
	}
	return nil
}

func (m *Message) maxAVPsFor(cmd *dict.Command) int {
	if m.Header.CommandFlags&RequestFlag == RequestFlag {
		return len(cmd.Request.Rule)
	}
	return len(cmd.Answer.Rule)
}

func (m *Message) decodeAVPs(b []byte, dictionary *dict.Snapshot) error {
	var a *AVP
	var decodeErrs *decodeErrors
	var err error
	for n := 0; n < len(b); {
		a, err = decodeAVP(b[n:], m.Header.ApplicationID, dictionary, 0, false)
		if err != nil {
			var lengthErr *avpLengthError
			if errors.As(err, &lengthErr) {
				return &MessageError{
					ResultCode: InvalidAVPLength,
					FailedAVP:  lengthErr.failedAVP,
					Err:        lengthErr,
				}
			}
			// Recoverable payload errors preserve their bytes as Unknown. A nil
			// Data value means framing failed and there is no safe next offset.
			if a.Data == nil {
				return err
			}
			decodeErrs = decodeErrs.add(err)
		}
		advance := a.Len()
		// RFC 6733 section 4.1 requires the next AVP to begin on a 32-bit
		// boundary. Validate the padded wire length before advancing.
		if advance <= 0 || advance > len(b)-n {
			lengthErr := newDecodedAVPLengthError(a, fmt.Errorf(
				"%w: AVP at offset %d consumes %d padded bytes, have %d",
				errAVPDataTooShort, n, advance, len(b)-n))
			return &MessageError{
				ResultCode: InvalidAVPLength,
				FailedAVP:  lengthErr.failedAVP,
				Err:        lengthErr,
			}
		}
		m.AVP = append(m.AVP, a)
		if failed := unknownMandatoryHierarchy(a, m.Header.ApplicationID, dictionary); failed != nil {
			m.unknownMandatoryAVPs = append(m.unknownMandatoryAVPs, failed)
		}
		n += advance
	}
	if decodeErrs != nil {
		// Depending on the settings, this will be thrown by the state machine or passed to the best handler
		m.DecodeErr = fmt.Errorf("failed to decode one or more AVPs: {%w}", decodeErrs)
	}
	return nil
}

// NewMessage creates and initializes a Message.
func NewMessage(cmd uint32, flags uint8, appid, hopbyhop, endtoend uint32, dictionary *dict.Parser) *Message {
	if hopbyhop == 0 {
		hopbyhop = rand.Uint32()
	}
	if endtoend == 0 {
		endtoend = rand.Uint32()
	}
	return &Message{
		Header: &Header{
			Version:       1,
			MessageLength: HeaderLength,
			CommandFlags:  flags,
			CommandCode:   cmd,
			ApplicationID: appid,
			HopByHopID:    hopbyhop,
			EndToEndID:    endtoend,
		},
		dictionary: dictionary,
		stream:     InvalidStreamID,
	}
}

// NewRequest creates a request for command cmd of application appid, with
// the command flags its definition in dictionary requires: R, and P when
// the request's Command Code Format carries PXY (RFC 6733 §3 and §3.2), as
// recorded by the definition's proxiable attribute. The definition is the
// one Message.Validate checks the request against, so the flags pass its
// check. A command that dictionary does not define, or whose definition
// does not state the P bit, gets R alone. A nil dictionary means
// dict.Default.
//
// Use NewMessage to choose every flag.
func NewRequest(cmd uint32, appid uint32, dictionary *dict.Parser) *Message {
	m := NewMessage(cmd, RequestFlag, appid, 0, 0, dictionary)
	if command, err := m.Dictionary().Snapshot().FindCommand(appid, cmd); err == nil {
		if proxiable := command.Request.Proxiable; proxiable != nil && *proxiable {
			m.Header.CommandFlags |= ProxiableFlag
		}
	}
	return m
}

// Dictionary returns the dictionary parser object associated with this
// message. This dictionary is used to encode and decode the message.
// If no dictionary is associated then it returns the default dictionary.
func (m *Message) Dictionary() *dict.Parser {
	if m.dictionary == nil {
		return dict.Default
	}
	return m.dictionary
}

// NewAVP creates and initializes a new AVP and adds it to the Message.
// It is not safe for concurrent calls.
func (m *Message) NewAVP(code uint32, flags uint8, vendor uint32, data datatype.Type) (*AVP, error) {
	// RFC 6733 §4.3.1: locally supplied addresses must have a valid family and length.
	switch address := data.(type) {
	case datatype.Address:
		if err := address.Valid(); err != nil {
			return nil, err
		}
	case *datatype.Address:
		if address == nil {
			return nil, errors.New("nil Address")
		}
		if err := address.Valid(); err != nil {
			return nil, err
		}
		data = *address
	}
	a := NewAVP(code, flags, vendor, data)
	m.AVP = append(m.AVP, a)
	m.Header.MessageLength += uint32(a.Len())
	return a, nil
}

// NewAVPByName resolves name in the message's application dictionary, then
// creates an AVP with the definition's code and Vendor-Id.
// It is not safe for concurrent calls.
func (m *Message) NewAVPByName(name string, flags uint8, data datatype.Type) (*AVP, error) {
	definition, err := m.Dictionary().FindAVPByName(m.Header.ApplicationID, name)
	if err != nil {
		return nil, err
	}
	return m.NewAVP(definition.Code, flags, definition.VendorID, data)
}

// AddAVP adds the AVP to the Message. It is not safe for concurrent calls.
func (m *Message) AddAVP(a *AVP) {
	m.AVP = append(m.AVP, a)
	m.Header.MessageLength += uint32(a.Len())
}

// InsertAVP inserts the AVP to the Message as the first AVP. It is not
// safe for concurrent calls.
func (m *Message) InsertAVP(a *AVP) {
	m.AVP = append([]*AVP{a}, m.AVP...)
	m.Header.MessageLength += uint32(a.Len())
}

// DeleteAVP removes all AVPs matching the given code and vendor ID from the
// Message. It returns the number of AVPs removed. It is not safe for
// concurrent calls.
func (m *Message) DeleteAVP(code, vendorID uint32) int {
	n := 0
	filtered := m.AVP[:0]
	for _, a := range m.AVP {
		if a.Code == code && a.VendorID == vendorID {
			m.Header.MessageLength -= uint32(a.Len())
			n++
		} else {
			filtered = append(filtered, a)
		}
	}
	m.AVP = filtered
	return n
}

var writerBufferPool sync.Pool

func newWriterBuffer(min int) *bytes.Buffer {
	if min > MessageBufferLength {
		return bytes.NewBuffer(make([]byte, min))
	}
	if v := writerBufferPool.Get(); v != nil {
		return v.(*bytes.Buffer)
	}
	return bytes.NewBuffer(make([]byte, MessageBufferLength))
}

func putWriterBuffer(b *bytes.Buffer) {
	b.Reset()
	if cap(b.Bytes()) == MessageBufferLength {
		writerBufferPool.Put(b)
	}
}

// WriteTo serializes the Message and writes into the writer.
func (m *Message) WriteTo(writer io.Writer) (int64, error) {
	n, err := m.WriteToStream(writer, m.stream)
	return int64(n), err
}

// WriteToStream serializes the Message and writes into the writer with given retries if needed
func (m *Message) WriteToWithRetry(writer io.Writer, retries uint) (int64, error) {
	n, err := m.WriteToStreamWithRetry(writer, m.stream, retries)
	return int64(n), err
}

// WriteToStream serializes the Message and writes into the writer
// If writer implements MultistreamWriter, writes the message into specified stream
func (m *Message) WriteToStream(writer io.Writer, stream uint) (n int, err error) {
	return m.WriteToStreamWithRetry(writer, stream, 0)
}

// WriteToStreamWithRetry serializes the Message and writes into the writer with specified number of retries
// if needed
// If writer implements MultistreamWriter, writes the message into specified stream
func (m *Message) WriteToStreamWithRetry(writer io.Writer, stream, retries uint) (n int, err error) {
	l, err := m.serializedLength()
	if err != nil {
		return 0, err
	}
	buf := newWriterBuffer(l)
	defer putWriterBuffer(buf)
	b := buf.Bytes()[0:l]
	if err := m.serializeTo(b, l); err != nil {
		return 0, err
	}
	switch w := writer.(type) {
	case MultistreamWriter:
		return writeStreamRetry(w, b, stream, retries)
	default:
		return writeRetry(writer, b, retries)
	}
}

func writeRetry(w io.Writer, b []byte, retries uint) (n int, err error) {
	var wn int
	for {
		wn, err = w.Write(b)
		n += wn
		if err == nil || retries == 0 {
			return
		}
		if nerr, isNetErr := err.(net.Error); !isNetErr || !nerr.Timeout() {
			return
		}
		if wn > 0 {
			b = b[wn:]
		}
		retries--
	}
}

func writeStreamRetry(w MultistreamWriter, b []byte, stream, retries uint) (n int, err error) {
	var wn int
	for {
		wn, err = w.WriteStream(b, stream)
		n += wn
		if err == nil || retries == 0 {
			return
		}
		if nerr, isNetErr := err.(net.Error); !isNetErr || !nerr.Timeout() {
			return
		}
		if wn > 0 {
			b = b[wn:]
		}
		retries--
	}
}

// Serialize returns the serialized bytes of the Message.
func (m *Message) Serialize() ([]byte, error) {
	l, err := m.serializedLength()
	if err != nil {
		return nil, err
	}
	b := make([]byte, l)
	if err := m.serializeTo(b, l); err != nil {
		return nil, err
	}
	return b, nil
}

// SerializeTo writes the serialized bytes of the Message into b.
func (m *Message) SerializeTo(b []byte) (err error) {
	l, err := m.serializedLength()
	if err != nil {
		return err
	}
	return m.serializeTo(b, l)
}

// serializeTo is shared by all message writers after the length check.
// It writes l, the computed length, rather than Header.MessageLength, which
// goes stale when an AVP is changed through a pointer (FindAVP, Unmarshal into
// *AVP fields). Serializing never writes to m, so one message can be
// serialized and read by several goroutines at once.
func (m *Message) serializeTo(b []byte, l int) (err error) {
	m.Header.SerializeTo(b[0:HeaderLength])
	// RFC 6733 §3: Message Length covers the header and the padded AVPs.
	putUint24(b[1:4], uint32(l))
	offset := HeaderLength
	for _, avp := range m.AVP {
		if err = avp.SerializeTo(b[offset:]); err != nil {
			return err
		}
		offset += avp.Len()
	}
	return nil
}

func (m *Message) serializedLength() (int, error) {
	l := m.Len()
	if l < HeaderLength {
		return 0, fmt.Errorf("invalid Diameter message length %d", l)
	}
	if l > MaxMessageLength {
		return 0, fmt.Errorf("diameter message length %d exceeds 24-bit maximum %d", l, MaxMessageLength)
	}
	return l, nil
}

// Len returns the length of the Message in bytes.
func (m *Message) Len() int {
	l := HeaderLength
	for _, avp := range m.AVP {
		l += avp.Len()
	}
	return l
}

// AVPRef identifies an AVP by its code and Vendor-Id. An AVP is identified by
// its code and its Vendor-Id together (RFC 6733 §4.1): one code denotes
// different AVPs in different vendors' spaces.
type AVPRef struct {
	Code     uint32
	VendorID uint32
}

// members returns the members of a Grouped AVP: none when a is nil or not
// Grouped, including when its Data is a nil *GroupedAVP.
func members(a *AVP) []*AVP {
	if group, ok := a.Data.(*GroupedAVP); ok && group != nil {
		return group.AVP
	}
	return nil
}

// findAVPs appends to found the AVPs among avps, and inside their Grouped
// AVPs at any depth, that carry key's code and Vendor-Id, in depth-first
// order. With first, it stops at the first one.
func findAVPs(found, avps []*AVP, key avpKey, first bool) []*AVP {
	for _, a := range avps {
		if a == nil {
			continue
		}
		if a.Code == key.Code && a.VendorID == key.VendorID {
			found = append(found, a)
			if first {
				return found
			}
		}
		if group := members(a); len(group) > 0 {
			n := len(found)
			found = findAVPs(found, group, key, first)
			if first && len(found) > n {
				return found
			}
		}
	}
	return found
}

// avpsWithPath returns the AVPs at the end of path, where path[0] is among
// avps and each following element is a member of the Grouped AVP before it.
func avpsWithPath(avps []*AVP, path []AVPRef) []*AVP {
	if len(path) == 0 {
		return avps
	}
	var found []*AVP
	for _, a := range avps {
		if a == nil || a.Code != path[0].Code || a.VendorID != path[0].VendorID {
			continue
		}
		if len(path) == 1 {
			found = append(found, a)
			continue
		}
		found = append(found, avpsWithPath(members(a), path[1:])...)
	}
	return found
}

// ErrAVPNotFound indicates that a message contains no AVP matching the lookup.
var ErrAVPNotFound = errors.New("AVP not found in message")

// findAVP is FindAVP and, with all, FindAVPs.
func (m *Message) findAVP(code, vendorID uint32, all bool) ([]*AVP, error) {
	key := avpKey{code, vendorID}
	found := findAVPs(nil, m.AVP, key, !all)
	if len(found) == 0 {
		return nil, fmt.Errorf("AVP %d of vendor %d: %w", key.Code, key.VendorID, ErrAVPNotFound)
	}
	return found, nil
}

// FindAVPs returns every AVP of the Message, at the top level and inside
// Grouped AVPs at any depth, depth-first, whose code and Vendor-Id are
// those of code and vendorID. A miss wraps ErrAVPNotFound.
//
// vendorID is the AVP's Vendor-Id, 0 for an IETF AVP, and is always
// matched (RFC 6733 §4.1). A code needs no dictionary.
//
// Example:
//
//	avps, err := m.FindAVPs(avp.SupportedVendorID, 0)
//	avps, err := m.FindAVPs(avp.SubscriptionData, 10415)
func (m *Message) FindAVPs(code, vendorID uint32) ([]*AVP, error) {
	return m.findAVP(code, vendorID, true)
}

// FindAVP returns the first AVP that FindAVPs would return.
//
// Example:
//
//	a, err := m.FindAVP(avp.OriginHost, 0)
//	a, err := m.FindAVP(avp.VisitedPLMNID, 10415)
func (m *Message) FindAVP(code, vendorID uint32) (*AVP, error) {
	found, err := m.findAVP(code, vendorID, false)
	if err != nil {
		return nil, err
	}
	return found[0], nil
}

// FindAVPsByName resolves name in the message's application dictionary and
// finds every AVP with its code and Vendor-Id. A missing definition wraps
// dict.ErrNotFound; an absent AVP wraps ErrAVPNotFound.
func (m *Message) FindAVPsByName(name string) ([]*AVP, error) {
	definition, err := m.Dictionary().FindAVPByName(m.Header.ApplicationID, name)
	if err != nil {
		return nil, err
	}
	return m.FindAVPs(definition.Code, definition.VendorID)
}

// FindAVPByName resolves name in the message's application dictionary and
// finds the first AVP with its code and Vendor-Id. A missing definition wraps
// dict.ErrNotFound; an absent AVP wraps ErrAVPNotFound.
func (m *Message) FindAVPByName(name string) (*AVP, error) {
	definition, err := m.Dictionary().FindAVPByName(m.Header.ApplicationID, name)
	if err != nil {
		return nil, err
	}
	return m.FindAVP(definition.Code, definition.VendorID)
}

// FindAVPsWithPath returns the AVPs reached by path through the Grouped
// AVP hierarchy: path[0] is an AVP at the top level of the Message and
// each following element a member of the Grouped AVP before it. Each
// element is matched by its own code and Vendor-Id, as in FindAVPs, since
// the members of a vendor's Grouped AVP can belong to another vendor's
// space. An empty path returns the top-level AVPs; a path that leads
// nowhere returns none.
//
// Example:
//
//	avps := m.FindAVPsWithPath(
//		diam.AVPRef{Code: avp.SubscriptionData, VendorID: 10415},
//		diam.AVPRef{Code: avp.APNConfigurationProfile, VendorID: 10415},
//		diam.AVPRef{Code: avp.APNConfiguration, VendorID: 10415},
//		diam.AVPRef{Code: avp.ServiceSelection},
//	)
func (m *Message) FindAVPsWithPath(path ...AVPRef) []*AVP {
	return avpsWithPath(m.AVP, path)
}

// Answer creates an answer for the current Message
// with optinal ResultCode AVP
func (m *Message) Answer(resultCode uint32) *Message {
	nm := NewMessage(
		m.Header.CommandCode,
		// RFC 6733 §3: an answer clears R, and T "MUST NOT be set in answer
		// messages"; E marks error answers only, so a fresh answer starts
		// without it. Reserved bits must be zero when sent (§3).
		// Only P keeps the request's value (§6.2).
		m.Header.CommandFlags&ProxiableFlag,
		m.Header.ApplicationID,
		m.Header.HopByHopID,
		m.Header.EndToEndID,
		m.Dictionary(),
	)
	// RFC 6733 §3: an answer copies both identifiers from its request,
	// including zero values. NewMessage generates IDs only for new messages.
	nm.Header.HopByHopID = m.Header.HopByHopID
	nm.Header.EndToEndID = m.Header.EndToEndID
	if resultCode != 0 {
		if _, err := nm.NewAVP(avp.ResultCode, avp.Mbit, 0, datatype.Unsigned32(resultCode)); err != nil {
			panic(err)
		}
	}
	nm.stream = m.stream
	return nm
}

func (m *Message) String() string {
	var b bytes.Buffer
	var typ string
	if m.Header.CommandFlags&RequestFlag == RequestFlag {
		typ = "Request"
	} else {
		typ = "Answer"
	}
	if dictCMD, err := m.Dictionary().FindCommand(
		m.Header.ApplicationID,
		m.Header.CommandCode,
	); err != nil {
		fmt.Fprintf(&b, "Unknown-%s\n%s\n", typ, m.Header)
	} else {
		fmt.Fprintf(&b, "%s-%s (%s%c)\n%s\n",
			dictCMD.Name,
			typ,
			dictCMD.Short,
			typ[0],
			m.Header,
		)
	}
	for _, a := range m.AVP {
		if dictAVP, err := m.Dictionary().FindAVP(
			m.Header.ApplicationID,
			a.Code,
			a.VendorID,
		); err != nil {
			fmt.Fprintf(&b, "\tUnknown %s (%s)\n", a, err)
		} else if a.Data.Type() == GroupedAVPType {
			fmt.Fprintf(&b, "\t%s %s\n", dictAVP.Name, printGrouped("\t", m, a, 1))
		} else {
			fmt.Fprintf(&b, "\t%s %s\n", dictAVP.Name, a)
		}
	}
	return b.String()
}

func printGrouped(prefix string, m *Message, a *AVP, indent int) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "{Code:%d,Flags:0x%x,Length:%d,VendorId:%d,Value:Grouped{\n",
		a.Code,
		a.Flags,
		a.Len(),
		a.VendorID,
	)
	for _, ga := range members(a) {
		if dictAVP, err := m.Dictionary().FindAVP(
			m.Header.ApplicationID,
			ga.Code,
			ga.VendorID,
		); err != nil {
			if dictAVP != nil {
				fmt.Fprintf(&b, "%s\t%s %s (%s),\n", prefix, dictAVP.Name, ga, err)
			} else {
				fmt.Fprintf(&b, "%s\tUnknown %s (%s),\n", prefix, ga, err)
			}
		} else {
			if ga.Data.Type() == GroupedAVPType {
				indent++
				tabs := indentTabs(indent)
				fmt.Fprintf(&b, "%s%s %s\n", tabs, dictAVP.Name, printGrouped(tabs, m, ga, indent))
			} else {
				fmt.Fprintf(&b, "%s\t%s %s,\n", prefix, dictAVP.Name, ga)
			}
		}
	}
	fmt.Fprintf(&b, "%s}}", prefix)
	return b.String()
}

func indentTabs(n int) string {
	var s string
	for i := 0; i < n; i++ {
		s += "\t"
	}
	return s
}

// Context returns the message's context. To change the context, use
// SetContext.
func (m *Message) Context() context.Context {
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

// SetContext replaces the message's context.
func (m *Message) SetContext(ctx context.Context) {
	m.ctx = ctx
}

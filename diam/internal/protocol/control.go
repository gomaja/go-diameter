package protocol

import (
	"io"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/internal/base"
)

type control struct {
	command                     uint32
	reservation                 Reservation
	header                      diam.Header
	frame                       *diam.Message
	logical, answered, released bool
	written                     bool
	writers                     int
	attempts                    uint
}
type operation struct {
	control                                           *control
	message                                           diam.ProtocolMessageMetadata
	length                                            int64
	required, closeAfter, handshake, reported, queued bool
	notice                                            *Notification
}

func metadata(m *diam.Message) diam.ProtocolMessageMetadata {
	var out diam.ProtocolMessageMetadata
	if m != nil {
		out.Stream = m.MessageStream()
		if m.Header != nil {
			out.Header = *m.Header
			out.HasHeader = true
		}
	}
	return out
}
func (c *Core) reserve(es []Effect, command uint32) []Effect {
	e := c.effect(ReserveIDs)
	e.Command = command
	e.Token = c.token()
	c.reservations[e.Token] = command
	return append(es, e)
}
func (c *Core) reserved(es []Effect, in Input) []Effect {
	cmd, ok := c.reservations[in.Token]
	if !ok {
		return es
	}
	delete(c.reservations, in.Token)
	if in.Err != nil {
		if c.phase >= Closed {
			return es
		}
		if cmd == diam.CapabilitiesExchange {
			c.handshake = newHandshakeResult(in.Err, nil)
		}
		return c.terminate(es, Closed)
	}
	if c.phase >= Closed || cmd == diam.DeviceWatchdog && c.phase != Open {
		e := c.effect(ReleaseIDs)
		e.Reservation = in.Reservation
		return append(es, e)
	}
	var m *diam.Message
	var err error
	switch cmd {
	case diam.CapabilitiesExchange:
		m, err = base.BuildCER(c.cfg.Dictionary, c.cfg.Local)
	case diam.DeviceWatchdog:
		m, err = base.BuildDWR(c.cfg.Dictionary, c.cfg.Local, uint32(c.cfg.Local.OriginStateID))
	case diam.DisconnectPeer:
		m, err = base.BuildDPR(c.cfg.Dictionary, c.cfg.Local, c.closeCause)
	}
	r := &control{command: cmd, reservation: in.Reservation, logical: true}
	c.controls[cmd] = r
	if err != nil {
		if cmd == diam.CapabilitiesExchange {
			c.handshake = newHandshakeResult(err, nil)
		}
		return c.terminate(es, Closed)
	}
	m.Header.HopByHopID = in.Reservation.Hop
	m.Header.EndToEndID = in.Reservation.End
	r.header = *m.Header
	r.frame = copyMessage(m)
	return c.send(es, m, r, false, false, false, nil)
}
func (c *Core) send(es []Effect, m *diam.Message, r *control, required, closeAfter, handshake bool, notice *Notification, source ...*diam.Message) []Effect {
	token := c.token()
	op := c.spareOperation
	c.spareOperation = nil
	if op == nil {
		op = new(operation)
	}
	*op = operation{control: r, length: int64(m.Len()), required: required, closeAfter: closeAfter, handshake: handshake, notice: notice}
	if notice != nil {
		op.message = notice.Message
	}
	if len(source) != 0 {
		op.message = metadata(source[0])
	}
	c.operations[token] = op
	if r != nil {
		r.writers++
		r.attempts++
	}
	e := c.effect(Send)
	e.Token = token
	e.Message = m
	if notice != nil {
		e.Notification = *notice
	}
	e.Required = required
	e.CloseAfter = closeAfter
	if c.cfg.QueueWrites {
		e.Stage = QueueStage
	} else {
		e.Stage = WrittenStage
	}
	return append(es, e)
}
func (c *Core) release(es []Effect, r *control) []Effect {
	if r.logical || r.writers != 0 || r.released {
		return es
	}
	r.released = true
	if c.controls[r.command] == r {
		delete(c.controls, r.command)
	}
	e := c.effect(ReleaseIDs)
	e.Reservation = r.reservation
	return append(es, e)
}
func (c *Core) settle(es []Effect, r *control) []Effect {
	r.logical = false
	r.answered = true
	return c.release(es, r)
}
func (c *Core) writeResult(es []Effect, in Input) []Effect {
	if in.Stage > SkippedStage {
		return es
	}
	op := c.operations[in.Token]
	if op == nil {
		return es
	}
	if in.Stage == SkippedStage && op.control != nil {
		return c.skippedControl(es, in, op)
	}

	terminal := in.Stage != QueueStage || in.Err != nil
	err := in.Err
	if in.Stage == SkippedStage && err == nil {
		err = io.ErrShortWrite
	}
	if in.Stage == WrittenStage && err == nil {
		expected := in.ExpectedBytes
		if expected == 0 {
			expected = op.length
		}
		if in.Bytes != expected {
			err = io.ErrShortWrite
		}
		if err == nil && op.control != nil {
			op.control.written = true
		}
	}
	if in.Stage == QueueStage {
		if op.queued {
			return es
		}
		op.queued = err == nil
	}
	if terminal {
		delete(c.operations, in.Token)
		defer c.recycleOperation(op)
		if op.control != nil {
			op.control.writers--
			es = c.release(es, op.control)
		}
	}
	if c.phase >= Closed {
		return es
	}
	if err != nil {
		if c.cfg.KeepCERDeadlineAfterTransportLoss && c.phase == WaitCEA && op.control != nil && op.control.command == diam.CapabilitiesExchange {
			c.handshake = newHandshakeResult(err, nil)
		}
		es = c.terminate(es, Closed)
		if op.required {
			n := Notification{Protocol: diam.ProtocolReplyFailure, Reply: diam.ProtocolReplyFailed, ReplyCode: in.ReplyCode, Closing: true, Message: op.message}
			if !op.reported && op.notice != nil && op.notice.Protocol != "" {
				n = *op.notice
				n.Reply, n.ReplyCode, n.Closing = diam.ProtocolReplyFailed, in.ReplyCode, true
			}
			es = append(es, c.notify(n))
		}
		return es
	}
	if in.Stage == WrittenStage && op.control != nil && op.control.command == diam.DisconnectPeer && c.earlyDPA != nil {
		saved := *c.earlyDPA
		return c.completeDPA(es, saved, saved.ResultCode)
	}
	if op.closeAfter && in.Stage == WrittenStage {
		es = c.terminate(es, Closed)
	}
	boundary := in.Stage == WrittenStage || c.cfg.QueueWrites
	if !boundary || op.reported {
		return es
	}
	op.reported = true
	if op.notice != nil {
		n := *op.notice
		n.ReplyCode = in.ReplyCode
		if in.Stage == QueueStage {
			n.Reply = diam.ProtocolReplyQueued
		} else {
			n.Reply = diam.ProtocolReplyWritten
		}
		es = append(es, c.notify(n))
	}

	if op.handshake && c.phase == Open {
		es = append(es, c.handshakeReady())
	}
	if op.control != nil && op.control.logical {
		if op.control.command == diam.DeviceWatchdog {
			es = c.watchdogPublished(es, in)
		}
		if op.control.command == diam.CapabilitiesExchange && c.cfg.CERInterval > 0 {
			es = c.arm(es, RetryTimer, in.At, c.cfg.CERInterval)
		}
	}
	return es
}

// #108/#125 and RFC 6733 §§3,5.6: gate cancellation ends a selected writer,
// not the connection. A published CER still owns correlation across retries.
func (c *Core) skippedControl(es []Effect, in Input, op *operation) []Effect {
	delete(c.operations, in.Token)
	defer c.recycleOperation(op)
	r := op.control
	logical := r.logical
	r.writers--
	if r.writers == 0 && !r.written {
		r.logical = false
	}
	es = c.release(es, r)
	if c.cfg.KeepCERDeadlineAfterTransportLoss && c.phase == WaitCEA && r.command == diam.CapabilitiesExchange {
		// A native closed gate is still the synchronous CER attempt's public
		// error. Its skipped writer pin has already been disposed above.
		err := in.Err
		if err == nil {
			err = io.ErrShortWrite
		}
		c.handshake = newHandshakeResult(err, nil)
		return c.terminate(es, Closed)
	}
	if r.command == diam.DeviceWatchdog && !r.written && logical {
		c.wdNext = nil
		c.wd.Pending = false
		if c.cfg.Watchdog && c.phase == Open && c.timers[WatchdogTimer].Token == 0 {
			es = c.watchdogArm(es, in.At, in.Interval)
		}
	}
	return es
}
func (c *Core) matches(r *control, m *diam.Message) bool {
	return r != nil && r.logical && m != nil && m.Header != nil && m.Header.ApplicationID == 0 && m.Header.CommandFlags&diam.RequestFlag == 0 &&
		m.Header.CommandCode == r.command && m.Header.HopByHopID == r.header.HopByHopID && m.Header.EndToEndID == r.header.EndToEndID
}

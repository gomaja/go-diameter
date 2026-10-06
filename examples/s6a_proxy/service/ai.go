// package servce implements S6a GRPC proxy service which sends AIR, ULR messages over diameter connection,
// waits (blocks) for diameter's AIAs, ULAs & returns their RPC representation
package service

import (
	"fmt"
	"log/slog"
	"math/rand"
	"strings"
	"time"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
	"github.com/gomaja/go-diameter/diam/sm/smpeer"
	"github.com/gomaja/go-diameter/examples/s6a_proxy/protos"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sendAIR - sends AIR with given Session ID (sid)
func (s *s6aProxy) sendAIR(sid string, req *protos.AuthenticationInformationRequest) error {
	slog.Debug("sending AIR", "session_id", sid, "request", req)
	c := s.conn
	meta, ok := smpeer.FromContext(c.Context())
	if !ok {
		return Errorf(codes.Internal, "peer metadata unavailable for AIR")
	}
	// randomize stream of first message and append it to SID to test SCTP multi-streaming support
	stream := uint(rand.Int31n(diam.MaxOutboundSCTPStreams - 2))
	sid = fmt.Sprintf("%s;stream:%d", sid, stream)
	for i := stream; i > 0; i-- {
		sid += " " // variable len
	}
	m, err := newAIR(s.cfg, meta, sid, req)
	if err != nil {
		return err
	}

	writer, isMulti := c.Connection().(diam.MultistreamWriter)
	if !isMulti {
		return Errorf(codes.FailedPrecondition, "AIR requires a multistream Diameter connection")
	}
	// randomize stream of first message to test SCTP multistreaming support
	// and send the AIR in two pieces to simulate message fragmentation
	mBytes, err := m.Serialize()
	if err != nil {
		return Error(codes.DataLoss, err)
	}
	l2 := len(mBytes) / 2
	// Don't allow simultaneous sends on the same stream, take stream scoped lock
	s.airSendLocks[stream].Lock()
	defer s.airSendLocks[stream].Unlock()

	_, err = writer.WriteStream(mBytes[:l2], stream)
	if err != nil {
		return Error(codes.DataLoss, err)
	}
	time.Sleep(time.Millisecond * 3)
	_, err = writer.WriteStream(mBytes[l2:], stream)
	if err != nil {
		return Error(codes.DataLoss, err)
	}
	return nil
}

// newAIR builds the Authentication-Information-Request for req, with Session
// ID sid, to the HSS that meta describes, and checks it against the
// dictionary's AIR grammar.
func newAIR(cfg *S6aProxyConfig, meta *smpeer.Metadata, sid string, req *protos.AuthenticationInformationRequest) (*diam.Message, error) {
	var irp uint32
	if req.ImmediateResponsePreferred {
		irp = 1
	}
	// NewRequest sets R and P, as the AIR's "REQ, PXY" header requires.
	m := diam.NewRequest(diam.AuthenticationInformation, diam.TGPP_S6A_APP_ID, dict.Default)
	if err := addAVP(m, avp.SessionID, avp.Mbit, 0, datatype.UTF8String(sid)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.OriginHost, avp.Mbit, 0, datatype.DiameterIdentity(cfg.Host)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.OriginRealm, avp.Mbit, 0, datatype.DiameterIdentity(cfg.Realm)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.DestinationRealm, avp.Mbit, 0, meta.OriginRealm); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.DestinationHost, avp.Mbit, 0, meta.OriginHost); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.UserName, avp.Mbit, 0, datatype.UTF8String(req.UserName)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.AuthSessionState, avp.Mbit, 0, datatype.Enumerated(1)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.VisitedPLMNID, avp.Vbit|avp.Mbit, VENDOR_3GPP, datatype.OctetString(req.VisitedPlmn)); err != nil {
		return nil, err
	}
	authInfo := &diam.GroupedAVP{
		AVP: []*diam.AVP{
			diam.NewAVP(
				avp.NumberOfRequestedVectors,
				avp.Vbit|avp.Mbit,
				VENDOR_3GPP,
				datatype.Unsigned32(req.NumRequestedEutranVectors)),
			diam.NewAVP(
				avp.ImmediateResponsePreferred, avp.Vbit|avp.Mbit, VENDOR_3GPP, datatype.Unsigned32(irp)),
		},
	}
	if len(req.ResyncInfo) > 0 {
		resyncInfo := diam.NewAVP(avp.ResynchronizationInfo, avp.Vbit|avp.Mbit, VENDOR_3GPP,
			datatype.OctetString(req.ResyncInfo))
		authInfo.AddAVP(resyncInfo)
	}
	if err := addAVP(m, avp.RequestedEUTRANAuthenticationInfo, avp.Vbit|avp.Mbit, VENDOR_3GPP, authInfo); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, Error(codes.Internal, err)
	}
	return m, nil
}

// S6a AIA
func handleAIA(s *s6aProxy) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		slog.Debug("received AIA", "remote_addr", c.RemoteAddr(), "message", m)
		var aia AIA
		err := m.Unmarshal(&aia)
		if err != nil {
			slog.Warn("dropping AIA: unmarshal failed", "remote_addr", c.RemoteAddr(), "message", m, "error", err)
			return
		}
		s.sessionsMu.Lock()

		var msgStream uint
		idx := strings.LastIndex(aia.SessionID, ";stream:")
		if idx < 0 {
			s.sessionsMu.Unlock()
			slog.Warn("dropping AIA: Session-Id has no stream marker",
				"session_id", aia.SessionID, "remote_addr", c.RemoteAddr(), "message", m)
			return
		}
		sid := aia.SessionID[0:idx]
		if _, err = fmt.Sscanf(aia.SessionID[idx:], ";stream:%d", &msgStream); err != nil {
			s.sessionsMu.Unlock()
			slog.Warn("dropping AIA: Session-Id has an invalid stream marker",
				"session_id", aia.SessionID, "remote_addr", c.RemoteAddr(), "message", m, "error", err)
			return
		}
		ch, ok := s.sessions[sid]
		if ok {
			// Use the stream from the message, not the connection's current stream,
			// since handlers may run concurrently.
			stream := m.MessageStream()
			if stream != msgStream {
				delete(s.sessions, sid)
				s.sessionsMu.Unlock()
				close(ch)
				slog.Warn("dropping AIA: received on another stream than its Session-Id names",
					"session_id", aia.SessionID, "session_stream", msgStream, "message_stream", stream,
					"remote_addr", c.RemoteAddr(), "message", m)
				return
			}
			delete(s.sessions, sid)
			s.sessionsMu.Unlock()
			ch <- &aia
		} else {
			s.sessionsMu.Unlock()
			slog.Warn("dropping AIA: no pending AIR for its session",
				"session_id", aia.SessionID, "remote_addr", c.RemoteAddr(), "message", m)
		}
	}
}

// AuthenticationInformation sends AIR over diameter connection,
// waits (blocks) for AIA & returns its RPC representation
func (s *s6aProxy) AuthenticationInformationImpl(
	req *protos.AuthenticationInformationRequest) (*protos.AuthenticationInformationAnswer, error) {
	slog.Debug("received AI request from gateway")
	res := &protos.AuthenticationInformationAnswer{}
	if req == nil {
		return res, Errorf(codes.InvalidArgument, "Nil AI Request")
	}

	sid := genSID()
	ch := make(chan interface{})
	s.updateSession(sid, ch)

	var (
		err     error
		retries = MAX_DIAM_RETRIES
		c       diam.Conn
	)
	for ; retries >= 0; retries-- {
		c, err = s.acquireConnection()
		if err != nil {
			s.releaseConnection()
			s.cleanupSession(sid)
			slog.Warn("cannot connect to HSS", "network", s.cfg.Protocol, "address", s.cfg.HssAddr, "error", err)
			return res, Error(codes.Unavailable, err)
		}
		err = s.sendAIR(sid, req)
		s.releaseConnection() // we can unlock reader after send
		if err != nil {
			slog.Warn("sending AIR failed", "session_id", sid, "error", err)
			if status, ok := status.FromError(err); ok && status != nil && status.Code() == codes.DataLoss {
				s.cleanupConn(c)
				continue
			}
		}
		break
	}

	if err == nil {
		select {
		case resp, open := <-ch:
			if open {
				aia, ok := resp.(*AIA)
				if ok {
					err = TranslateBaseDiamResultCode(aia.ResultCode)
					res.ErrorCode = protos.ErrorCode(aia.ExperimentalResult.ExperimentalResultCode)
					for _, ai := range aia.AIs {
						res.EutranVectors = append(
							res.EutranVectors,
							&protos.AuthenticationInformationAnswer_EUTRANVector{
								Rand:  ai.EUtranVector.RAND.Serialize(),
								Xres:  ai.EUtranVector.XRES.Serialize(),
								Autn:  ai.EUtranVector.AUTN.Serialize(),
								Kasme: ai.EUtranVector.KASME.Serialize()})
					}
					return res, err // the only successful "exit" is here
				} else {
					err = Errorf(codes.Internal, "Invalid Response Type: %T, AIA expected.", resp)
				}
			} else {
				err = Errorf(codes.Aborted, "AIR for Session ID: %s is canceled", sid)
			}
		case <-time.After(time.Second * TIMEOUT_SECONDS):
			err = Errorf(codes.DeadlineExceeded, "AIR Timed Out for Session ID: %s", sid)
		}
	}
	s.cleanupSession(sid)
	return res, err
}

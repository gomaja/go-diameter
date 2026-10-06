// package servce implements S6a GRPC proxy service which sends AIR, ULR messages over diameter connection,
// waits (blocks) for diameter's AIAs, ULAs & returns their RPC representation
package service

import (
	"log/slog"
	"math/rand"
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

// sendULR - sends ULR with given Session ID (sid)
func (s *s6aProxy) sendULR(sid string, req *protos.UpdateLocationRequest) error {
	c := s.conn

	meta, ok := smpeer.FromContext(c.Context())
	if !ok {
		return Errorf(codes.Internal, "peer metadata unavailable for ULR")
	}
	m, err := newULR(s.cfg, meta, sid, req)
	if err != nil {
		return err
	}

	// randomize stream of first message and append it to SID to test SCTP multi-streaming support
	stream := uint(rand.Int31n(diam.MaxOutboundSCTPStreams - 2))
	s.airSendLocks[stream].Lock()
	defer s.airSendLocks[stream].Unlock()
	_, err = m.WriteToStream(c, stream)
	if err != nil {
		err = Error(codes.DataLoss, err)
	}
	return err
}

// newULR builds the Update-Location-Request for req, with Session ID sid,
// to the HSS that meta describes, and checks it against the dictionary's
// ULR grammar.
func newULR(cfg *S6aProxyConfig, meta *smpeer.Metadata, sid string, req *protos.UpdateLocationRequest) (*diam.Message, error) {
	// NewRequest sets R and P, as the ULR's "REQ, PXY" header requires.
	m := diam.NewRequest(diam.UpdateLocation, diam.TGPP_S6A_APP_ID, dict.Default)
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
	if err := addAVP(m, avp.RATType, avp.Mbit, VENDOR_3GPP, datatype.Enumerated(ULR_RAT_TYPE)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.ULRFlags, avp.Vbit|avp.Mbit, VENDOR_3GPP, datatype.Unsigned32(ULR_FLAGS)); err != nil {
		return nil, err
	}
	if err := addAVP(m, avp.VisitedPLMNID, avp.Vbit|avp.Mbit, VENDOR_3GPP, datatype.OctetString(req.VisitedPlmn)); err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, Error(codes.Internal, err)
	}
	return m, nil
}

// S6a ULA
func handleULA(s *s6aProxy) diam.HandlerFunc {
	return func(c diam.Conn, m *diam.Message) {
		var ula ULA
		err := m.Unmarshal(&ula)
		if err != nil {
			slog.Warn("dropping ULA: unmarshal failed", "remote_addr", c.RemoteAddr(), "message", m, "error", err)
			return
		}
		s.sessionsMu.Lock()
		ch, ok := s.sessions[ula.SessionID]
		if ok {
			delete(s.sessions, ula.SessionID)
			s.sessionsMu.Unlock()
			ch <- &ula
		} else {
			s.sessionsMu.Unlock()
			slog.Warn("dropping ULA: no pending ULR for its session",
				"session_id", ula.SessionID, "remote_addr", c.RemoteAddr(), "message", m)
		}
	}
}

// UpdateLocation sends ULR (Code 316) over diameter connection,
// waits (blocks) for ULAA & returns its RPC representation
func (s *s6aProxy) UpdateLocationImpl(req *protos.UpdateLocationRequest) (*protos.UpdateLocationAnswer, error,
) {
	res := &protos.UpdateLocationAnswer{}
	if req == nil {
		return res, Errorf(codes.InvalidArgument, "Nil UL Request")
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
		err = s.sendULR(sid, req)

		s.releaseConnection() // we can unlock reader after send

		if err != nil {
			slog.Warn("sending ULR failed", "session_id", sid, "error", err)
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
				ula, ok := resp.(*ULA)
				if ok {
					err = TranslateBaseDiamResultCode(ula.ResultCode)
					res.ErrorCode = protos.ErrorCode(ula.ExperimentalResult.ExperimentalResultCode)
					res.DefaultContextId = ula.SubscriptionData.APNConfigurationProfile.ContextIdentifier
					res.TotalAmbr = &protos.UpdateLocationAnswer_AggregatedMaximumBitrate{
						MaxBandwidthUl: ula.SubscriptionData.AMBR.MaxRequestedBandwidthUL,
						MaxBandwidthDl: ula.SubscriptionData.AMBR.MaxRequestedBandwidthDL,
					}
					res.AllApnsIncluded =
						ula.SubscriptionData.APNConfigurationProfile.AllAPNConfigurationsIncludedIndicator == 0

					for _, apnCfg := range ula.SubscriptionData.APNConfigurationProfile.APNConfigs {
						res.Apn = append(
							res.Apn,
							&protos.UpdateLocationAnswer_APNConfiguration{
								ContextId:        apnCfg.ContextIdentifier,
								ServiceSelection: apnCfg.ServiceSelection,
								QosProfile: &protos.UpdateLocationAnswer_APNConfiguration_QoSProfile{
									ClassId:                 apnCfg.EPSSubscribedQoSProfile.QoSClassIdentifier,
									PriorityLevel:           apnCfg.EPSSubscribedQoSProfile.AllocationRetentionPriority.PriorityLevel,
									PreemptionCapability:    apnCfg.EPSSubscribedQoSProfile.AllocationRetentionPriority.PreemptionCapability == 0,
									PreemptionVulnerability: apnCfg.EPSSubscribedQoSProfile.AllocationRetentionPriority.PreemptionVulnerability == 0,
								},
								Ambr: &protos.UpdateLocationAnswer_AggregatedMaximumBitrate{
									MaxBandwidthUl: apnCfg.AMBR.MaxRequestedBandwidthUL,
									MaxBandwidthDl: apnCfg.AMBR.MaxRequestedBandwidthDL,
								},
							})
					}
					return res, err
				} else {
					err = Errorf(codes.Internal, "Invalid Response Type: %T, ULA expected.", resp)
				}
			} else {
				err = Errorf(codes.Aborted, "ULR for Session ID: %s is canceled", sid)
			}
		case <-time.After(time.Second * TIMEOUT_SECONDS):
			err = Errorf(codes.DeadlineExceeded, "ULR Timed Out for Session ID: %s", sid)
		}
	}
	s.cleanupSession(sid)
	return res, err
}

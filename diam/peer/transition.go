package peer

// PeerState names the RFC 6733 §5.6 peer state machine states.
type PeerState string

const (
	Closed           PeerState = "Closed"
	WaitConnAck      PeerState = "Wait-Conn-Ack"
	WaitICEA         PeerState = "Wait-I-CEA"
	WaitConnAckElect PeerState = "Wait-Conn-Ack/Elect"
	WaitReturns      PeerState = "Wait-Returns"
	IOpen            PeerState = "I-Open"
	ROpen            PeerState = "R-Open"
	Closing          PeerState = "Closing"
)

type psmEvent string

const (
	start       psmEvent = "Start"
	rConnCER    psmEvent = "R-Conn-CER"
	iAck        psmEvent = "I-Rcv-Conn-Ack"
	iNack       psmEvent = "I-Rcv-Conn-Nack"
	timeout     psmEvent = "Timeout"
	iCEA        psmEvent = "I-Rcv-CEA"
	iDisc       psmEvent = "I-Peer-Disc"
	rDisc       psmEvent = "R-Peer-Disc"
	iNonCEA     psmEvent = "I-Rcv-Non-CEA"
	winElection psmEvent = "Win-Election"
	sendMessage psmEvent = "Send-Message"
	iMessage    psmEvent = "I-Rcv-Message"
	rMessage    psmEvent = "R-Rcv-Message"
	iDWR        psmEvent = "I-Rcv-DWR"
	rDWR        psmEvent = "R-Rcv-DWR"
	iDWA        psmEvent = "I-Rcv-DWA"
	rDWA        psmEvent = "R-Rcv-DWA"
	stop        psmEvent = "Stop"
	iDPR        psmEvent = "I-Rcv-DPR"
	rDPR        psmEvent = "R-Rcv-DPR"
	iDPA        psmEvent = "I-Rcv-DPA"
	rDPA        psmEvent = "R-Rcv-DPA"
)

type psmStep struct {
	next    PeerState
	actions string
}

// psmTable transcribes every RFC 6733 §5.6 state/event row. Event payloads,
// generation checks and failed Process-CER/CEA guards precede this table.
var psmTable = map[PeerState]map[psmEvent]psmStep{
	// RFC 6733 §5.6 Closed: initiate I or accept and answer the first R CER.
	Closed: {
		start:    {WaitConnAck, "I-Snd-Conn-Req"},
		rConnCER: {ROpen, "R-Accept,Process-CER,R-Snd-CEA"},
	},
	// RFC 6733 §5.6 Wait-Conn-Ack: retain R as an election candidate.
	WaitConnAck: {
		iAck: {WaitICEA, "I-Snd-CER"}, iNack: {Closed, "Cleanup"},
		rConnCER: {WaitConnAckElect, "R-Accept,Process-CER"}, timeout: {Closed, "Error"},
	},
	// RFC 6733 §5.6 Wait-I-CEA: process only matching I-CEA as success.
	WaitICEA: {
		iCEA: {IOpen, "Process-CEA"}, rConnCER: {WaitReturns, "R-Accept,Process-CER,Elect"},
		iDisc: {Closed, "I-Disc"}, iNonCEA: {Closed, "Error"}, timeout: {Closed, "Error"},
	},
	// RFC 6733 §5.6 Wait-Conn-Ack/Elect: dial failure selects R.
	WaitConnAckElect: {
		iAck: {WaitReturns, "I-Snd-CER,Elect"}, iNack: {ROpen, "R-Snd-CEA"},
		rDisc: {WaitConnAck, "R-Disc"}, rConnCER: {WaitConnAckElect, "R-Reject"},
		timeout: {Closed, "Error"},
	},
	// RFC 6733 §§5.6, 5.6.4 Wait-Returns: winner discards I, loser R.
	WaitReturns: {
		winElection: {ROpen, "I-Disc,R-Snd-CEA"}, iDisc: {ROpen, "I-Disc,R-Snd-CEA"},
		iCEA: {IOpen, "R-Disc"}, rDisc: {WaitICEA, "R-Disc"},
		rConnCER: {WaitReturns, "R-Reject"}, timeout: {Closed, "Error"},
	},
	// RFC 6733 §§5.4–5.6 R-Open: answer watchdog and disconnect requests.
	ROpen: {
		sendMessage: {ROpen, "R-Snd-Message"}, rMessage: {ROpen, "Process"},
		rDWR: {ROpen, "Process-DWR,R-Snd-DWA"}, rDWA: {ROpen, "Process-DWA"},
		rConnCER: {ROpen, "R-Reject"}, stop: {Closing, "R-Snd-DPR"},
		rDPR: {Closing, "R-Snd-DPA"}, rDisc: {Closed, "R-Disc"},
	},
	// RFC 6733 §§5.4–5.6 I-Open: answer watchdog and disconnect requests.
	IOpen: {
		sendMessage: {IOpen, "I-Snd-Message"}, iMessage: {IOpen, "Process"},
		iDWR: {IOpen, "Process-DWR,I-Snd-DWA"}, iDWA: {IOpen, "Process-DWA"},
		rConnCER: {IOpen, "R-Reject"}, stop: {Closing, "I-Snd-DPR"},
		iDPR: {Closing, "I-Snd-DPA"}, iDisc: {Closed, "I-Disc"},
	},
	// RFC 6733 §§5.4, 5.6 Closing: DPA, disconnect, or timeout retires the leg.
	Closing: {
		iDPA: {Closed, "I-Disc"}, rDPA: {Closed, "R-Disc"},
		timeout: {Closed, "Error"}, iDisc: {Closed, "I-Disc"}, rDisc: {Closed, "R-Disc"},
	},
}

func transition(state PeerState, event psmEvent) (psmStep, bool) {
	r, ok := psmTable[state][event]
	return r, ok
}

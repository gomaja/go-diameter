package sm

// DisconnectCause is the reason carried in a DPR (RFC 6733 §5.4.3).
type DisconnectCause uint32

const (
	DisconnectRebooting            DisconnectCause = 0
	DisconnectBusy                 DisconnectCause = 1
	DisconnectDoNotWantToTalkToYou DisconnectCause = 2
)

package inspector

import (
	"github.com/redborder/redborder-flow-agent/internal/capture"
)

// PortState tracks the TCP connection handshake state.
type PortState uint8

const (
	StateNone PortState = iota
	StateSYNSent
	StateSYNReceived
	StateEstablished
	StateClosed
)

// EvaluateTCPFlags updates the TCP state based on packet flags.
// Returns the updated state and whether the target port is confirmed open/responsive.
func EvaluateTCPFlags(flags uint8, isForward bool, currentState PortState) (PortState, bool) {
	hasSYN := flags&capture.FlagSYN != 0
	hasACK := flags&capture.FlagACK != 0
	hasRST := flags&capture.FlagRST != 0
	hasFIN := flags&capture.FlagFIN != 0

	if hasRST {
		return StateClosed, false
	}
	if hasFIN {
		return StateClosed, currentState == StateEstablished
	}

	if hasSYN && !hasACK {
		return StateSYNSent, false
	}
	if hasSYN && hasACK {
		return StateSYNReceived, true // SYN-ACK confirms listening service port
	}
	if hasACK && (currentState == StateSYNReceived || currentState == StateSYNSent) {
		return StateEstablished, true
	}

	// If session already established or active bidirectional ACK traffic observed
	isOpen := currentState == StateEstablished || currentState == StateSYNReceived
	return currentState, isOpen
}

package sshutils

const (
	// WindowChangeRequest is a request to change window.
	WindowChangeRequest = "window-change"
)

// WinChangeReqParams specifies parameters for window changes
type WinChangeReqParams struct {
	W   uint32
	H   uint32
	Wpx uint32
	Hpx uint32
}

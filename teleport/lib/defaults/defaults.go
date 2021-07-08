package defaults

import "time"

const (
	// TerminalResizePeriod is how long to wait before updating the size of the
	// terminal window.
	TerminalResizePeriod = 2 * time.Second
)

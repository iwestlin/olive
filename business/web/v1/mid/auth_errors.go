// Package mid contains the set of middleware functions.
package mid

import "errors"

var (
	errAuthDisabled = errors.New("authentication subsystem disabled")
	errNoSession    = errors.New("missing session credentials")
	errBadSession   = errors.New("invalid or expired session")
)
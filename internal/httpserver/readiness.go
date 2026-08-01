package httpserver

import "sync/atomic"

// Readiness is the process-local initialization and shutdown gate. Dependency
// health is checked separately for each ready request.
type Readiness struct {
	ready    atomic.Bool
	onChange func(bool)
}

// NewReadiness creates a not-ready gate.
func NewReadiness(onChange func(bool)) *Readiness {
	state := &Readiness{onChange: onChange}
	if onChange != nil {
		onChange(false)
	}
	return state
}

// Set updates readiness and its metric callback.
func (r *Readiness) Set(ready bool) {
	if r == nil {
		return
	}
	previous := r.ready.Swap(ready)
	if previous != ready && r.onChange != nil {
		r.onChange(ready)
	}
}

// IsReady reports the current lifecycle gate.
func (r *Readiness) IsReady() bool {
	return r != nil && r.ready.Load()
}

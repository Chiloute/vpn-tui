// Package health holds reconnection timing helpers.
package health

import "time"

// Backoff yields exponentially growing delays: Initial, 2*Initial, 4*Initial… capped at Max.
type Backoff struct{ Initial, Max time.Duration }

// Delay returns the wait before attempt (>= 1). Initial defaults to 1s; Max 0 means no cap.
func (b Backoff) Delay(attempt int) time.Duration {
	d := b.Initial
	if d <= 0 {
		d = time.Second
	}
	for i := 1; i < attempt; i++ {
		if b.Max > 0 && d >= b.Max {
			break
		}
		d *= 2
	}
	if b.Max > 0 && d > b.Max {
		d = b.Max
	}
	return d
}

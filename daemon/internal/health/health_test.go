package health

import (
	"testing"
	"time"
)

func TestDelay(t *testing.T) {
	b := Backoff{Initial: time.Second, Max: 5 * time.Second}
	for i, w := range []time.Duration{1, 2, 4, 5, 5, 5} {
		if g := b.Delay(i + 1); g != w*time.Second {
			t.Fatalf("attempt %d: %v", i+1, g)
		}
	}
	if g := (Backoff{}).Delay(3); g != 4*time.Second {
		t.Fatal(g)
	}
	if g := b.Delay(1000); g != 5*time.Second {
		t.Fatal(g)
	}
}

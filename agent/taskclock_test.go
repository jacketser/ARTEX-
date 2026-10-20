package agent

import (
	"testing"
	"time"
)

func TestMovableDeadlineKeepsIndependentLimits(t *testing.T) {
	tc := TaskClock{Flexible: true, DeadlineUnix: time.Now().Unix() + 5}
	if d, c := runMaxDuration(tc, 60*time.Second); d != 60*time.Second || c {
		t.Fatal(d, c)
	}
	if d, c := runMaxDuration(tc, 0); d != 0 || c {
		t.Fatal(d, c)
	}
	tc.Final = true
	tc.DeadlineUnix = time.Now().Unix() - 60
	if d, c := runMaxDuration(tc, 0); d != time.Second || !c {
		t.Fatal("final round unbounded", d, c)
	}
	tc.Final = false
	tc.Flexible = false
	if d, c := runMaxDuration(tc, 60*time.Second); d != time.Second || !c {
		t.Fatal(d, c)
	}
}

package upstream

import (
	"errors"
	"testing"
	"time"
)

func TestFreshness(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	f := NewFreshness(func() time.Time { return now })
	if f.Fresh("a", time.Minute) {
		t.Fatal("an unconfirmed key is fresh")
	}
	f.Confirm("a")
	now = now.Add(30 * time.Second)
	f.Confirm("b")
	if !f.Fresh("a", time.Minute) || !f.Fresh("b", time.Minute) {
		t.Fatal("confirmed keys are not fresh")
	}
	now = now.Add(31 * time.Second)
	if f.Fresh("a", time.Minute) || !f.Fresh("b", time.Minute) {
		t.Fatal("freshness does not follow the window")
	}
	f.Prune(time.Minute)
	f.mu.Lock()
	_, a := f.m["a"]
	_, b := f.m["b"]
	f.mu.Unlock()
	if a || !b {
		t.Fatalf("after Prune: a kept %v, b kept %v", a, b)
	}
}

func TestAnswered(t *testing.T) {
	for _, tt := range []struct {
		err  error
		want bool
	}{
		{&Error{Op: "GET", Status: 404, Err: ErrNotFound}, true},
		{&Error{Op: "GET", Status: 403, Err: ErrDenied}, true},
		{&Error{Op: "GET", Status: 503, Err: ErrUnavailable}, false},
		{&Error{Op: "GET", Status: 401, Err: ErrAuth}, false},
		{errors.New("other"), false},
	} {
		if got := Answered(tt.err); got != tt.want {
			t.Errorf("Answered(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

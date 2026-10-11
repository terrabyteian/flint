package gc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandleStart(t *testing.T) {
	e := newTestEnv(t, nil)
	garbage := e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	paused, resume := make(chan struct{}), make(chan struct{})
	e.setHook(func(s Step) {
		if s == StepMarked {
			close(paused)
			<-resume
		}
	})
	start := func(body string) (int, any) {
		r := httptest.NewRequest("POST", "/api/v1/gc", strings.NewReader(body))
		return e.c.HandleStart(r, "alice")
	}

	for _, body := range []string{`{"dryRun": "yes"}`, `{"dry": true}`, `{"dryRun": true} {}`, `[`} {
		if status, v := start(body); status != http.StatusBadRequest {
			t.Errorf("start with %s = %d %+v, want 400", body, status, v)
		}
	}
	status, v := start(`{"dryRun": true}`)
	rep, ok := v.(*Report)
	if status != http.StatusAccepted || !ok || !rep.DryRun || rep.State != StateRunning || rep.Actor != "alice" || rep.Trigger != TriggerAPI {
		t.Fatalf("start = %d %+v", status, v)
	}
	<-paused
	if status, v := start(""); status != http.StatusConflict || !strings.Contains(v.(apiError).Error, "already in progress") {
		t.Errorf("second start = %d %+v", status, v)
	}
	status, v = e.c.HandleStatus(httptest.NewRequest("GET", "/api/v1/gc", nil), "alice")
	if st := v.(Status); status != 200 || st.Running == nil || !st.Running.DryRun {
		t.Errorf("status during a run = %d %+v", status, v)
	}
	close(resume)
	e.c.Wait(context.Background())
	e.setHook(nil)
	if !e.exists(garbage) {
		t.Fatal("a dry run deleted a blob")
	}

	// An empty body runs a sweep.
	if status, _ := start(""); status != http.StatusAccepted {
		t.Fatalf("start = %d", status)
	}
	e.c.Wait(context.Background())
	_, v = e.c.HandleStatus(nil, "alice")
	b, _ := json.Marshal(v)
	var st struct {
		Running *Report
		Last    struct {
			DryRun  bool
			State   string
			Deleted Count
		}
		GracePeriod string
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	if st.Running != nil || st.Last.DryRun || st.Last.State != StateSucceeded || st.Last.Deleted.Blobs != 1 || st.GracePeriod != "24h0m0s" {
		t.Errorf("status JSON = %s", b)
	}
	if e.exists(garbage) {
		t.Error("the sweep left the garbage")
	}

	e.c.Close()
	if status, _ := start(""); status != http.StatusServiceUnavailable {
		t.Errorf("start after Close = %d", status)
	}
}

func TestHandleStartBodyLimit(t *testing.T) {
	e := newTestEnv(t, nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/gc", strings.NewReader(`{"dryRun": true, "x": "`+strings.Repeat("x", 100)+`"}`))
	r.Body = http.MaxBytesReader(w, r.Body, 10)
	if status, _ := e.c.HandleStart(r, "alice"); status != http.StatusRequestEntityTooLarge {
		t.Errorf("start with an oversized body = %d", status)
	}
}

// TestSchedule runs garbage collection on its interval, counting from the
// start of the last run, also across restarts.
func TestSchedule(t *testing.T) {
	defer func(d time.Duration) { scheduleDelay = d }(scheduleDelay)
	scheduleDelay = 10 * time.Millisecond
	// The schedule waits real time; the collector's clock follows it.
	clk := &clock{t: time.Now()}
	stopClock := make(chan struct{})
	defer close(stopClock)
	go func() {
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stopClock:
				return
			case <-tick.C:
				clk.mu.Lock()
				clk.t = time.Now()
				clk.mu.Unlock()
			}
		}
	}()
	e := newTestEnv(t, func(o *Options) { o.Interval = 50 * time.Millisecond; o.Now = clk.now })
	st := e.c.Status()
	if st.Interval != "50ms" || st.NextRun == nil || st.NextRun.After(time.Now().Add(time.Second)) {
		t.Fatalf("status before any run = %+v", st)
	}
	runs := make(chan *Report, 10)
	e.setHook(func(s Step) {
		if s == StepMarked {
			runs <- e.c.snapshot()
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		e.c.RunSchedule(ctx)
		close(done)
	}()
	var starts []time.Time
	for range 3 {
		select {
		case r := <-runs:
			if r.Trigger != TriggerSchedule || r.Actor != "system" || r.DryRun {
				t.Errorf("scheduled run = %+v", r)
			}
			starts = append(starts, r.Started)
		case <-time.After(5 * time.Second):
			t.Fatal("no scheduled run")
		}
	}
	cancel()
	<-done
	for i := 1; i < len(starts); i++ {
		if gap := starts[i].Sub(starts[i-1]); gap < 45*time.Millisecond {
			t.Errorf("runs %d and %d started %s apart, want the 50ms interval", i-1, i, gap)
		}
	}
	st = e.c.Status()
	if want := st.Last.Started.Add(50 * time.Millisecond); st.NextRun == nil || !st.NextRun.Equal(want) {
		t.Errorf("next run %v, want %v", st.NextRun, want)
	}

	// A run started through the API delays the schedule.
	paused, resume := make(chan struct{}), make(chan struct{})
	e.setHook(func(s Step) {
		if s == StepMarked {
			select {
			case <-paused:
				select {
				case runs <- e.c.snapshot():
				default:
				}
			default:
				close(paused)
				<-resume
			}
		}
	})
	api, err := e.c.Start(RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	<-paused
	ctx, cancel = context.WithCancel(context.Background())
	done = make(chan struct{})
	go func() {
		e.c.RunSchedule(ctx)
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // the schedule is due, and finds the run in progress
	close(resume)
	select {
	case r := <-runs:
		if r.Trigger != TriggerSchedule || r.Started.Before(api.Started.Add(50*time.Millisecond)) {
			t.Errorf("scheduled run %+v; the run started through the API began at %v", r, api.Started)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no scheduled run after the run started through the API")
	}
	cancel()
	<-done
}

// TestNoSchedule returns at once without an interval.
func TestNoSchedule(t *testing.T) {
	e := newTestEnv(t, nil)
	done := make(chan struct{})
	go func() {
		e.c.RunSchedule(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunSchedule without an interval did not return")
	}
}

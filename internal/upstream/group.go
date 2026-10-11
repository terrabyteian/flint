package upstream

import (
	"context"
	"sync"
)

// Group collapses concurrent calls with the same key into one: the first
// caller starts the call, and callers that arrive while it runs wait for
// its result instead of asking the upstream again. The zero value is
// ready to use.
type Group[T any] struct {
	mu    sync.Mutex
	calls map[string]*call[T]
}

type call[T any] struct {
	done chan struct{}
	val  T
	err  error
}

// Do runs fn for key unless a call for key is already running, and
// returns that call's result. fn runs in its own goroutine with a context
// that keeps ctx's values but not its cancellation, so one caller giving
// up does not fail the others; fn must bound its own duration. A caller
// whose ctx ends stops waiting and gets ctx's error.
func (g *Group[T]) Do(ctx context.Context, key string, fn func(ctx context.Context) (T, error)) (T, error) {
	g.mu.Lock()
	if g.calls == nil {
		g.calls = map[string]*call[T]{}
	}
	c, ok := g.calls[key]
	if !ok {
		c = &call[T]{done: make(chan struct{})}
		g.calls[key] = c
		go func() {
			c.val, c.err = fn(context.WithoutCancel(ctx))
			g.mu.Lock()
			delete(g.calls, key)
			g.mu.Unlock()
			close(c.done)
		}()
	}
	g.mu.Unlock()
	select {
	case <-c.done:
		return c.val, c.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

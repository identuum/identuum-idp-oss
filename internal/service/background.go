package service

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/logger"
)

// BackgroundRunner runs work after the request that triggered it has been
// answered. The routes that must not reveal whether an account exists (password
// reset, verification resend, self-registration) hand the account-dependent part
// of their work to one, so their response time does not depend on it.
//
// A nil BackgroundRunner runs the work inline: the default, and what tests use
// to see the work's effects at once.
type BackgroundRunner func(ctx context.Context, work func(ctx context.Context))

// backgroundTimeout bounds one piece of detached work.
const backgroundTimeout = 30 * time.Second

// RunDetached runs work in its own goroutine, with a context that carries the
// request's values but outlives its cancellation, bounded by backgroundTimeout.
func RunDetached(ctx context.Context, work func(ctx context.Context)) {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), backgroundTimeout)
	go func() {
		defer cancel()
		// A panic on this goroutine would end the process, which no serving
		// path may do; the request that started it is already answered.
		defer func() {
			if r := recover(); r != nil {
				logger.ErrorContext(detached, "background work panicked", zap.Any("panic", r))
			}
		}()
		work(detached)
	}()
}

// runWith runs work through run, or inline when run is nil.
func runWith(run BackgroundRunner, ctx context.Context, work func(ctx context.Context)) {
	if run == nil {
		work(ctx)
		return
	}
	run(ctx, work)
}

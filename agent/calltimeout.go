package agent

import (
	"context"
	"fmt"
	"iter"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// The SDK retries connection establishment but does not bound the entire stream.
// This deadline includes connection retries, rate-limit waits and response consumption.
func callTimeoutFromEnv() time.Duration {
	value := strings.TrimSpace(os.Getenv("ARTEX_LLM_CALL_TIMEOUT"))
	if value == "" {
		return 10 * time.Minute
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil || n < 0 || n > int64((1<<63-1)/int64(time.Second)) {
		log.Print("[llm] invalid ARTEX_LLM_CALL_TIMEOUT; using 600 seconds")
		return 10 * time.Minute
	}
	return time.Duration(n) * time.Second
}

type CallTimeoutError struct{ Timeout time.Duration }

func (e *CallTimeoutError) Error() string {
	return fmt.Sprintf("llm call_timeout: model call exceeded %s", e.Timeout)
}
func (e *CallTimeoutError) Unwrap() error { return context.DeadlineExceeded }

type callTimeoutProvider struct {
	inner   llm.Provider
	timeout time.Duration
}

func wrapCallTimeout(p llm.Provider) llm.Provider {
	timeout := callTimeoutFromEnv()
	if p == nil || timeout == 0 {
		return p
	}
	return &callTimeoutProvider{inner: p, timeout: timeout}
}
func (p *callTimeoutProvider) resultError(parent, call context.Context, err error) error {
	if parent.Err() != nil {
		return parent.Err()
	}
	if call.Err() == context.DeadlineExceeded {
		return &CallTimeoutError{Timeout: p.timeout}
	}
	return err
}
func (p *callTimeoutProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		call, cancel := context.WithTimeout(ctx, p.timeout)
		defer cancel()
		for ev, err := range p.inner.Stream(call, req) {
			err = p.resultError(ctx, call, err)
			if !yield(ev, err) || err != nil {
				return
			}
		}
		// Some providers terminate their iterator silently on context cancellation.
		if err := p.resultError(ctx, call, nil); err != nil {
			yield(llm.StreamEvent{}, err)
		}
	}
}
func (p *callTimeoutProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	call, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	msg, stop, usage, err := p.inner.Complete(call, req)
	return msg, stop, usage, p.resultError(ctx, call, err)
}

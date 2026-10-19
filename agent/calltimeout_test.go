package agent

import (
	"context"
	"errors"
	"github.com/Autumn-27/norma/llm"
	"iter"
	"testing"
	"time"
)

type waitingProvider struct {
	silent  bool
	context context.Context
}

func (p *waitingProvider) Stream(ctx context.Context, _ llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		p.context = ctx
		if !yield(llm.StreamEvent{}, nil) {
			return
		}
		<-ctx.Done()
		if !p.silent {
			yield(llm.StreamEvent{}, ctx.Err())
		}
	}
}
func (p *waitingProvider) Complete(ctx context.Context, _ llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	<-ctx.Done()
	return llm.Message{}, "", llm.Usage{}, ctx.Err()
}
func TestCallTimeout(t *testing.T) {
	for _, silent := range []bool{false, true} {
		p := &callTimeoutProvider{inner: &waitingProvider{silent: silent}, timeout: 10 * time.Millisecond}
		var got error
		for _, err := range p.Stream(context.Background(), llm.CompletionRequest{}) {
			if err != nil {
				got = err
			}
		}
		var timeout *CallTimeoutError
		if !errors.As(got, &timeout) {
			t.Fatalf("silent=%v: %v", silent, got)
		}
	}
	p := &callTimeoutProvider{inner: &waitingProvider{}, timeout: 10 * time.Millisecond}
	_, _, _, err := p.Complete(context.Background(), llm.CompletionRequest{})
	var timeout *CallTimeoutError
	if !errors.As(err, &timeout) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _, err = p.Complete(ctx, llm.CompletionRequest{})
	if !errors.Is(err, context.Canceled) || errors.As(err, &timeout) {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, _, _, err = p.Complete(ctx, llm.CompletionRequest{})
	if !errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) {
		t.Fatal(err)
	}
}
func TestCallStreamEarlyStopCancels(t *testing.T) {
	inner := &waitingProvider{}
	p := &callTimeoutProvider{inner: inner, timeout: time.Hour}
	for range p.Stream(context.Background(), llm.CompletionRequest{}) {
		break
	}
	if inner.context.Err() != context.Canceled {
		t.Fatal("stream context leaked")
	}
}
func TestCallTimeoutConfiguration(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{{"", 10 * time.Minute}, {"0", 0}, {"12", 12 * time.Second}, {"-1", 10 * time.Minute}, {"9223372036854775807", 10 * time.Minute}} {
		t.Setenv("ARTEX_LLM_CALL_TIMEOUT", tc.value)
		if got := callTimeoutFromEnv(); got != tc.want {
			t.Fatalf("%q: %v", tc.value, got)
		}
	}
}

package tracing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type Record struct {
	Name         string    `json:"name"`
	TraceID      string    `json:"trace_id"`
	SpanID       string    `json:"span_id"`
	ParentSpanID string    `json:"parent_span_id"`
	StartTime    time.Time `json:"start_time"`
	EndTime      time.Time `json:"end_time"`
	Status       string    `json:"status"`
	Attempt      int64     `json:"attempt,omitempty"`
	HTTPStatus   int64     `json:"http_status,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
	ElapsedMS    *float64  `json:"elapsed_ms,omitempty"`
}

type exportItem struct {
	record Record
	flush  chan struct{}
}

type fileProcessor struct {
	queue     chan exportItem
	done      chan struct{}
	abort     chan struct{}
	abortOnce sync.Once
	mu        sync.RWMutex
	closed    bool
	started   bool
	maxBytes  int
	exported  atomic.Uint64
	dropped   atomic.Uint64
	failed    atomic.Uint64
}

func newFileProcessor(capacity, maxBytes int) *fileProcessor {
	return &fileProcessor{
		queue: make(chan exportItem, capacity), done: make(chan struct{}),
		abort: make(chan struct{}), maxBytes: maxBytes,
	}
}

func (processor *fileProcessor) start(writer io.WriteCloser) {
	processor.mu.Lock()
	defer processor.mu.Unlock()
	processor.started = true
	go processor.run(writer)
}

func (processor *fileProcessor) run(writer io.WriteCloser) {
	defer close(processor.done)
	defer func() {
		if err := writer.Close(); err != nil {
			processor.failed.Add(1)
		}
	}()
	written := 0
	failed := false
	for item := range processor.queue {
		if item.flush != nil {
			close(item.flush)
			continue
		}
		select {
		case <-processor.abort:
			processor.dropped.Add(1)
			continue
		default:
		}
		if failed {
			processor.dropped.Add(1)
			continue
		}
		encoded, err := json.Marshal(item.record)
		if err != nil || written+len(encoded)+1 > processor.maxBytes {
			processor.failed.Add(1)
			failed = true
			continue
		}
		encoded = append(encoded, '\n')
		count, err := writer.Write(encoded)
		if err != nil || count != len(encoded) {
			processor.failed.Add(1)
			failed = true
			continue
		}
		written += count
		processor.exported.Add(1)
	}
}

func (processor *fileProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}

func (processor *fileProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	if !span.SpanContext().IsSampled() || !allowedName(span.Name()) {
		return
	}
	parentID := span.Parent().SpanID()
	record := Record{
		Name: span.Name(), TraceID: span.SpanContext().TraceID().String(),
		SpanID: span.SpanContext().SpanID().String(), ParentSpanID: parentID.String(),
		StartTime: span.StartTime().UTC(), EndTime: span.EndTime().UTC(), Status: span.Status().Code.String(),
	}
	if span.Name() == UploadAttempt {
		for _, field := range span.Attributes() {
			switch string(field.Key) {
			case "attempt":
				if field.Value.Type() == attribute.INT64 && field.Value.AsInt64() > 0 {
					record.Attempt = field.Value.AsInt64()
				}
			case "http_status":
				if field.Value.Type() == attribute.INT64 && field.Value.AsInt64() >= 100 && field.Value.AsInt64() <= 599 {
					record.HTTPStatus = field.Value.AsInt64()
				}
			case "outcome":
				if field.Value.Type() == attribute.STRING && allowedUploadOutcome(field.Value.AsString()) {
					record.Outcome = field.Value.AsString()
				}
			}
		}
		if record.Attempt == 0 || record.Outcome == "" {
			processor.dropped.Add(1)
			return
		}
		elapsedMS := span.EndTime().Sub(span.StartTime()).Seconds() * 1000
		record.ElapsedMS = &elapsedMS
	}
	item := exportItem{record: record}
	processor.mu.RLock()
	defer processor.mu.RUnlock()
	if processor.closed || !processor.started {
		processor.dropped.Add(1)
		return
	}
	select {
	case processor.queue <- item:
	default:
		processor.dropped.Add(1)
	}
}

func (processor *fileProcessor) Shutdown(ctx context.Context) error {
	processor.mu.Lock()
	if !processor.closed {
		processor.closed = true
		close(processor.queue)
		if !processor.started {
			close(processor.done)
		}
	}
	processor.mu.Unlock()
	select {
	case <-processor.done:
		return nil
	case <-ctx.Done():
		processor.abortOnce.Do(func() { close(processor.abort) })
		return ctx.Err()
	}
}

func (processor *fileProcessor) ForceFlush(ctx context.Context) error {
	item := exportItem{flush: make(chan struct{})}
	processor.mu.RLock()
	if processor.closed || !processor.started {
		processor.mu.RUnlock()
		return nil
	}
	select {
	case processor.queue <- item:
		processor.mu.RUnlock()
	default:
		processor.mu.RUnlock()
		return errors.New("local trace queue is full")
	}
	select {
	case <-item.flush:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

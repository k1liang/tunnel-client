package tracing

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"sync"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

const sampledParent = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"

func TestRuntimeExportsSafeParentedSpans(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	runtime, err := New(runtimeconfig.TracingConfig{Enabled: true, File: path})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pollBaggage, err := baggage.Parse("secret=prompt")
	if err != nil {
		t.Fatal(err)
	}
	ctx = baggage.ContextWithBaggage(ctx, pollBaggage)
	ctx = (propagation.TraceContext{}).Extract(ctx, propagation.MapCarrier{"traceparent": "00-ffffffffffffffffffffffffffffffff-ffffffffffffffff-01", "tracestate": "secret=prompt"})
	ctx, dispatch := runtime.StartCommand(ctx, sampledParent)
	_, target := runtime.Start(ctx, MCP)
	target.SetAttributes(attribute.String("secret", "prompt"))
	target.AddEvent("private-payload")
	target.SetStatus(codes.Error, "private-auth-header")
	target.RecordError(errors.New("private-error"))
	target.End()
	_, upload := runtime.Start(ctx, Upload)
	upload.End()
	cancel()
	if ctx.Err() != context.Canceled {
		t.Fatal("command context lost cancellation")
	}
	if trace.SpanContextFromContext(ctx).TraceState().Len() != 0 {
		t.Fatal("poll tracestate leaked")
	}
	if baggage.FromContext(ctx).Len() != 0 {
		t.Fatal("poll baggage leaked")
	}
	dispatch.End()
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, raw := readRecords(t, path)
	if len(records) != 3 {
		t.Fatalf("got %d records", len(records))
	}
	for _, record := range records {
		if record.TraceID != "1234567890abcdef1234567890abcdef" || record.EndTime.Before(record.StartTime) {
			t.Fatalf("invalid record: %+v", record)
		}
		parent := dispatch.SpanContext().SpanID().String()
		if record.Name == Dispatch {
			parent = "1234567890abcdef"
		}
		if record.ParentSpanID != parent {
			t.Fatalf("unexpected parent: %+v", record)
		}
	}
	for _, forbidden := range []string{"secret", "prompt", "private", "attributes", "events", "resource", "tracestate", "ffffffff"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("trace contains forbidden field/value %q", forbidden)
		}
	}
	info, err := os.Stat(path)
	if err != nil || goruntime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("trace file permissions: %v %v", info, err)
	}
	if stats := runtime.Stats(); stats.Commands != 1 || stats.Exported != 3 || stats.Failed != 0 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestRuntimeRejectsCarriersAndRespectsSampling(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	runtime, err := New(runtimeconfig.TracingConfig{Enabled: true, File: path})
	if err != nil {
		t.Fatal(err)
	}
	parents := []string{"", "invalid", strings.Repeat("x", 10000), "00-00000000000000000000000000000000-1234567890abcdef-01", "00-1234567890abcdef1234567890abcdef-0000000000000000-01", strings.ToUpper(sampledParent), "01" + sampledParent[2:], sampledParent[:53] + "00"}
	for _, parent := range parents {
		ctx, command := runtime.StartCommand(context.Background(), parent)
		_, child := runtime.Start(ctx, MCP)
		if command.IsRecording() || child.IsRecording() {
			t.Fatalf("unexpected recording for %q", parent)
		}
		child.End()
		command.End()
	}
	ctx, command := runtime.StartCommand(context.Background(), sampledParent)
	_, forbidden := runtime.Start(ctx, "secret-operation")
	if forbidden.IsRecording() {
		t.Fatal("arbitrary span name allowed")
	}
	command.SetName("private-span-name")
	command.End()
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, _ := readRecords(t, path)
	if len(records) != 0 {
		t.Fatalf("unexpected records: %+v", records)
	}
	if stats := runtime.Stats(); stats.Missing != 1 || stats.Invalid != 6 || stats.Unsampled != 1 {
		t.Fatalf("unexpected carrier stats: %+v", stats)
	}
}

func TestUploadAttemptRequiresLocalUploadAndBoundsExportedFields(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	runtime, err := New(runtimeconfig.TracingConfig{Enabled: true, File: path})
	if err != nil {
		t.Fatal(err)
	}
	ctx, dispatch := runtime.StartCommand(context.Background(), sampledParent)
	if StartUploadAttempt(ctx, 1) != nil {
		t.Fatal("command span started an upload attempt")
	}
	uploadCtx, upload := runtime.Start(ctx, Upload)
	finish := StartUploadAttempt(uploadCtx, 1)
	if finish == nil {
		t.Fatal("missing upload attempt callback")
	}
	finish(999, "private-error")
	upload.End()
	dispatch.End()
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, raw := readRecords(t, path)
	if len(records) != 3 {
		t.Fatalf("unexpected record count: %d", len(records))
	}
	if strings.Contains(raw, "private") {
		t.Fatal("unbounded outcome leaked into trace")
	}
	for _, record := range records {
		if record.Name == UploadAttempt {
			if record.Attempt != 1 || record.HTTPStatus != 0 || record.Outcome != "request_error" || record.Status != "Error" {
				t.Fatalf("unexpected attempt record: %+v", record)
			}
			return
		}
	}
	t.Fatal("missing upload attempt")
}

func TestRuntimeDisabledAndExclusiveOutput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	disabled, err := New(runtimeconfig.TracingConfig{File: path})
	if err != nil || disabled.Enabled() {
		t.Fatalf("default enabled: %v", err)
	}
	for _, runtime := range []*Runtime{nil, disabled} {
		ctx := (propagation.TraceContext{}).Extract(context.Background(), propagation.MapCarrier{"traceparent": sampledParent})
		ctx, span := runtime.StartCommand(ctx, sampledParent)
		if trace.SpanContextFromContext(ctx).IsValid() || span.IsRecording() {
			t.Fatal("disabled command inherited poll parent")
		}
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("disabled runtime created file: %v", err)
	}
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{path, filepath.Dir(path), filepath.Join(path, "missing.jsonl")} {
		if _, err := New(runtimeconfig.TracingConfig{Enabled: true, File: invalid}); err == nil {
			t.Fatal("accepted existing or inaccessible path")
		}
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "existing" {
		t.Fatal("existing output modified")
	}
}

func TestConcurrentCommandsAndShutdown(t *testing.T) {
	t.Parallel()
	runtime, err := New(runtimeconfig.TracingConfig{Enabled: true, File: filepath.Join(t.TempDir(), "trace.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 64 {
		workers.Go(func() {
			<-start
			for range 20 {
				ctx, command := runtime.StartCommand(context.Background(), sampledParent)
				_, child := runtime.Start(ctx, MCP)
				child.End()
				command.End()
			}
		})
	}
	workers.Go(func() {
		<-start
		if err := runtime.Shutdown(context.Background()); err != nil {
			t.Error(err)
		}
	})
	close(start)
	workers.Wait()
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func readRecords(t *testing.T, path string) ([]Record, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var records []Record
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var record Record
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records, string(data)
}

func BenchmarkCommandSpans(b *testing.B) {
	runtime, err := New(runtimeconfig.TracingConfig{Enabled: true, File: filepath.Join(b.TempDir(), "trace.jsonl")})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = runtime.Shutdown(context.Background()) })
	b.ReportAllocs()
	for b.Loop() {
		ctx, command := runtime.StartCommand(context.Background(), sampledParent)
		_, target := runtime.Start(ctx, MCP)
		target.End()
		_, upload := runtime.Start(ctx, Upload)
		upload.End()
		command.End()
	}
}

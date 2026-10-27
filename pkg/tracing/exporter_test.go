package tracing

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
)

type gatedWriter struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (writer *gatedWriter) Write(data []byte) (int, error) {
	writer.once.Do(func() { close(writer.entered) })
	<-writer.release
	return len(data), nil
}

func (*gatedWriter) Close() error { return nil }

type failingWriter struct{ short bool }

func (writer failingWriter) Write(data []byte) (int, error) {
	if writer.short {
		return len(data) - 1, nil
	}
	return 0, errors.New("private disk failure")
}

func (failingWriter) Close() error { return nil }

func runtimeWithWriter(t *testing.T, writer io.WriteCloser) *Runtime {
	t.Helper()
	runtime, err := newRuntime(runtimeconfig.TracingConfig{Enabled: true, File: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	runtime.processor.start(writer)
	return runtime
}

func TestFullQueueAndBlockedExporterDoNotBlockCommands(t *testing.T) {
	t.Parallel()
	writer := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	runtime := runtimeWithWriter(t, writer)
	_, span := runtime.StartCommand(context.Background(), sampledParent)
	span.End()
	<-writer.entered
	for range queueCapacity + 1 {
		_, span := runtime.StartCommand(context.Background(), sampledParent)
		span.End()
	}
	if runtime.Stats().Dropped != 1 {
		t.Fatalf("expected one bounded queue drop: %+v", runtime.Stats())
	}
	if err := runtime.processor.ForceFlush(context.Background()); err == nil {
		t.Fatal("full queue flush should fail immediately")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("shutdown ignored cancellation: %v", err)
	}
	close(writer.release)
	<-runtime.processor.done
	stats := runtime.Stats()
	if stats.Exported != 1 || stats.Dropped != queueCapacity+1 {
		t.Fatalf("unexpected shutdown accounting: %+v", stats)
	}
}

func TestExporterFailuresAreIsolated(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		short    bool
		maxBytes int
	}{
		{name: "write-error", maxBytes: fileLimit},
		{name: "short-write", short: true, maxBytes: fileLimit},
		{name: "file-limit", maxBytes: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runtime := runtimeWithWriter(t, failingWriter{short: test.short})
			runtime.processor.maxBytes = test.maxBytes
			for range 2 {
				_, span := runtime.StartCommand(context.Background(), sampledParent)
				span.End()
			}
			if err := runtime.Shutdown(context.Background()); err != nil {
				t.Fatalf("export failure affected shutdown: %v", err)
			}
			stats := runtime.Stats()
			if stats.Exported != 0 || stats.Failed != 1 || stats.Dropped != 1 {
				t.Fatalf("unexpected failure accounting: %+v", stats)
			}
		})
	}
}

func TestForceFlushPreservesQueueOrderingAndCancellation(t *testing.T) {
	t.Parallel()
	writer := &gatedWriter{entered: make(chan struct{}), release: make(chan struct{})}
	runtime := runtimeWithWriter(t, writer)
	_, span := runtime.StartCommand(context.Background(), sampledParent)
	span.End()
	<-writer.entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.processor.ForceFlush(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("flush ignored cancellation: %v", err)
	}
	close(writer.release)
	if err := runtime.processor.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.Stats().Exported != 1 {
		t.Fatal("flush returned before export")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.processor.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
}

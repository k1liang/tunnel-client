package tracing

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"go.uber.org/fx"
)

func TestLifecycleDrainsAfterDependentShutdown(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	cfg := &runtimeconfig.TracingConfig{Enabled: true, File: path}
	app := fx.New(fx.NopLogger, fx.Supply(cfg), Module,
		fx.Invoke(func(lifecycle fx.Lifecycle, runtime *Runtime) {
			lifecycle.Append(fx.Hook{
				OnStart: func(context.Context) error {
					_, err := os.Stat(path)
					return err
				},
				OnStop: func(ctx context.Context) error {
					_, span := runtime.StartCommand(ctx, sampledParent)
					span.End()
					return nil
				},
			})
		}))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("file created before lifecycle startup")
	}
	if err := app.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := app.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	records, _ := readRecords(t, path)
	if len(records) != 1 || records[0].Name != Dispatch {
		t.Fatalf("shutdown lost final span: %+v", records)
	}
}

package dispatcherinternal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/openai/tunnel-client/pkg/controlplane"
	"github.com/openai/tunnel-client/pkg/mcpclient"
	"github.com/openai/tunnel-client/pkg/runtimeconfig"
	"github.com/openai/tunnel-client/pkg/tracing"
	"github.com/openai/tunnel-client/pkg/tunnelctx"
	"github.com/openai/tunnel-client/pkg/types"
)

func TestProcessorTracingUsesCommandParentAndPreservesResponses(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"success", "rpc_error", "write_error", "read_error", "upload_error", "cancel", "owned_meta", "owned_headers", "missing", "invalid", "unsampled"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "trace.jsonl")
			runtime, err := tracing.New(runtimeconfig.TracingConfig{Enabled: true, File: path})
			require.NoError(t, err)
			req := newTraceContextTestRequest(t, `{"name":"secret_tool","arguments":{"secret":"never export"}}`)
			if scenario == "owned_meta" {
				req = newTraceContextTestRequest(t, `{"_meta":{"traceparent":"customer-owned","baggage":"secret"}}`)
			}
			original := append(json.RawMessage(nil), req.Params...)
			response := &jsonrpc.Response{ID: req.ID, Result: json.RawMessage(`{"secret":"response"}`)}
			base := &scriptedForwardingConnection{statusCode: http.StatusOK, readSteps: []readStep{{msg: response}}}
			switch scenario {
			case "rpc_error":
				response.Result = nil
				response.Error = &jsonrpc.Error{Code: -32000, Message: "secret error"}
			case "write_error":
				base.writeErr = errors.New("secret write failure")
			case "read_error":
				base.readSteps = []readStep{{err: errors.New("secret read failure")}}
			}
			conn := &traceRecordingConnection{ForwardingConnection: base}
			responder := newRecordingResponder()
			var delivery controlplane.Responder = responder
			uploadError := errors.New("secret upload failure")
			if scenario == "upload_error" {
				delivery = &traceFailingResponder{recordingResponder: responder, err: uploadError}
			}
			processor := newTracingProcessor(t, runtime, &stubForwardingTransport{conn: conn}, delivery)
			parent := traceContextTestParent
			switch scenario {
			case "missing":
				parent = ""
			case "invalid":
				parent = "malformed"
			case "unsampled":
				parent = parent[:53] + "00"
			}
			command := &tracingPolledCommand{fakePolledCommand: &fakePolledCommand{id: "trace", message: req, shardToken: "token"}, parent: parent}
			if scenario == "owned_headers" {
				command.headers = http.Header{"Traceparent": {"00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"}, "Tracestate": {"caller=owned"}}
			}
			pollCtx := (propagation.TraceContext{}).Extract(t.Context(), propagation.MapCarrier{"traceparent": "00-11111111111111111111111111111111-2222222222222222-01"})
			if scenario == "cancel" {
				var cancel context.CancelFunc
				pollCtx, cancel = context.WithCancel(pollCtx)
				cancel()
			}
			processErr := processor.Process(pollCtx, command)
			switch scenario {
			case "cancel":
				require.ErrorIs(t, processErr, context.Canceled)
			case "upload_error":
				require.NoError(t, processErr)
				require.Equal(t, 1, conn.writes)
			default:
				require.NoError(t, processErr)
			}
			require.Equal(t, original, req.Params)
			if scenario == "owned_headers" {
				require.Equal(t, command.headers.Get("Traceparent"), conn.headers.Get("Traceparent"))
				require.Equal(t, command.headers.Get("Tracestate"), conn.headers.Get("Tracestate"))
			}
			require.NoError(t, runtime.Shutdown(context.Background()))
			records, raw := readTraceRecords(t, path)
			require.NotContains(t, raw, "secret")
			require.NotContains(t, raw, "customer-owned")
			if scenario == "missing" || scenario == "invalid" || scenario == "unsampled" {
				require.Empty(t, records)
				return
			}
			byName := map[string]tracing.Record{}
			for _, record := range records {
				require.Equal(t, parent[3:35], record.TraceID)
				byName[record.Name] = record
			}
			dispatch := byName[tracing.Dispatch]
			require.Equal(t, parent[36:52], dispatch.ParentSpanID)
			require.Equal(t, dispatch.SpanID, byName[tracing.MCP].ParentSpanID)
			if scenario != "cancel" {
				require.Len(t, records, 3)
				require.Equal(t, dispatch.SpanID, byName[tracing.Upload].ParentSpanID)
				require.False(t, byName[tracing.MCP].EndTime.After(byName[tracing.Upload].StartTime))
				responder.waitForResponse(t)
			}
			if scenario == "rpc_error" || scenario == "read_error" || scenario == "write_error" || scenario == "upload_error" || scenario == "cancel" {
				require.Equal(t, "Error", dispatch.Status)
			}
			if conn.request != nil {
				if scenario == "owned_meta" {
					require.Equal(t, original, conn.request.Params)
				} else {
					params := traceContextTestObject(t, conn.request.Params)
					meta := traceContextTestObject(t, params["_meta"])
					require.Contains(t, string(meta["traceparent"]), byName[tracing.MCP].SpanID)
					require.NotContains(t, meta, "tracestate")
				}
			}
		})
	}
}

func TestProcessorTracingConcurrentReverseCompletion(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "trace.jsonl")
	runtime, err := tracing.New(runtimeconfig.TracingConfig{Enabled: true, File: path})
	require.NoError(t, err)
	connections := map[string]*traceRecordingConnection{}
	commands := []*tracingPolledCommand{}
	for _, name := range []string{"a", "b"} {
		req := newTraceContextTestRequest(t, `{}`)
		connections[name] = &traceRecordingConnection{ForwardingConnection: &stubForwardingConnection{statusCode: http.StatusOK, response: &jsonrpc.Response{ID: req.ID, Result: json.RawMessage(`{}`)}}, entered: make(chan struct{}), release: make(chan struct{})}
		commands = append(commands, &tracingPolledCommand{fakePolledCommand: &fakePolledCommand{id: types.RequestID(name), message: req, shardToken: name}, parent: "00-" + strings.Repeat(name, 32) + "-" + strings.Repeat(name, 16) + "-01"})
	}
	responder := newRecordingResponder()
	processor := newTracingProcessor(t, runtime, traceRoutingTransport{connections}, responder)
	var workers sync.WaitGroup
	for _, cmd := range commands {
		workers.Go(func() { require.NoError(t, processor.Process(t.Context(), cmd)) })
	}
	for _, connection := range connections {
		select {
		case <-connection.entered:
		case <-t.Context().Done():
			t.Fatal("command did not enter")
		}
	}
	close(connections["b"].release)
	require.Equal(t, types.RequestID("b"), responder.waitForResponse(t).requestID)
	close(connections["a"].release)
	require.Equal(t, types.RequestID("a"), responder.waitForResponse(t).requestID)
	workers.Wait()
	require.NoError(t, runtime.Shutdown(context.Background()))
	records, _ := readTraceRecords(t, path)
	require.Len(t, records, 6)
	for _, command := range commands {
		var dispatchID string
		for _, record := range records {
			if record.TraceID == command.parent[3:35] && record.Name == tracing.Dispatch {
				dispatchID = record.SpanID
				require.Equal(t, command.parent[36:52], record.ParentSpanID)
			}
		}
		require.NotEmpty(t, dispatchID)
		for _, record := range records {
			if record.TraceID == command.parent[3:35] && record.Name != tracing.Dispatch {
				require.Equal(t, dispatchID, record.ParentSpanID)
			}
		}
	}
}

func newTracingProcessor(t *testing.T, runtime *tracing.Runtime, transport mcpclient.ForwardingTransport, responder controlplane.Responder) Processor {
	t.Helper()
	cfg := newTestMCPConfig(t, time.Second)
	cfg.ForwardTraceContext = true
	bindings := newTestChannelBindings(transport)
	binding := bindings[types.DefaultChannel]
	binding.TransportKind = runtimeconfig.MCPTransportHTTPStreamable
	bindings[types.DefaultChannel] = binding
	processor, err := NewProcessor(processorParams{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), ChannelBindings: bindings, TunnelResponder: responder, MCPConfig: cfg, OAuthHTTPClient: &http.Client{}, ControlPlaneCfg: newTestControlPlaneConfig(t), MeterProvider: newTestMeterProvider(t), Tracing: runtime})
	require.NoError(t, err)
	return processor
}

type tracingPolledCommand struct {
	*fakePolledCommand
	parent string
}

func (cmd *tracingPolledCommand) TraceContext() *types.TraceContext {
	if len(cmd.headers) > 0 {
		return nil
	}
	return cmd.CommandTraceContext()
}

func (cmd *tracingPolledCommand) CommandTraceContext() *types.TraceContext {
	return &types.TraceContext{Traceparent: cmd.parent, Tracestate: "untrusted=secret"}
}

type traceRoutingTransport struct {
	connections map[string]*traceRecordingConnection
}

func (transport traceRoutingTransport) Connect(ctx context.Context) (mcpclient.ForwardingConnection, error) {
	requestID, _ := tunnelctx.RequestIDFromContext(ctx)
	return transport.connections[requestID], nil
}

type traceRecordingConnection struct {
	mcpclient.ForwardingConnection
	writes  int
	request *jsonrpc.Request
	headers http.Header
	parent  trace.SpanContext
	entered chan struct{}
	release chan struct{}
}

func (conn *traceRecordingConnection) Write(ctx context.Context, headers http.Header, message jsonrpc.Message) (mcpclient.ForwardingWriteResult, error) {
	conn.writes++
	conn.request, _ = message.(*jsonrpc.Request)
	conn.headers = headers.Clone()
	conn.parent = trace.SpanContextFromContext(ctx)
	if conn.entered != nil {
		close(conn.entered)
		select {
		case <-conn.release:
		case <-ctx.Done():
			return mcpclient.ForwardingWriteResult{}, ctx.Err()
		}
	}
	return conn.ForwardingConnection.Write(ctx, headers, message)
}

type traceFailingResponder struct {
	*recordingResponder
	err error
}

func (responder *traceFailingResponder) PostResponse(ctx context.Context, requestID types.RequestID, response *types.TunnelResponse) (types.TunnelServiceRequestID, error) {
	identifier, _ := responder.recordingResponder.PostResponse(ctx, requestID, response)
	return identifier, responder.err
}

func readTraceRecords(t *testing.T, path string) ([]tracing.Record, string) {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var records []tracing.Record
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	for decoder.More() {
		var record tracing.Record
		require.NoError(t, decoder.Decode(&record))
		records = append(records, record)
	}
	return records, string(data)
}

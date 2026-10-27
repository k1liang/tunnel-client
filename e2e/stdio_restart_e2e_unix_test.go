//go:build !windows

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	harnesspkg "github.com/openai/tunnel-client/testsupport/e2e"
	"github.com/openai/tunnel-client/testsupport/mockmcpserver"
	"github.com/openai/tunnel-client/testsupport/mocktunnelservice"
)

func TestHarnessStdioRestartsChildAfterSuccessfulToolResponse(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	startupPipe := filepath.Join(dir, "child-startup.pipe")
	if err := syscall.Mkfifo(startupPipe, 0o600); err != nil {
		t.Fatalf("create child startup pipe: %v", err)
	}
	exitPipe := filepath.Join(dir, "child-exit.pipe")
	if err := syscall.Mkfifo(exitPipe, 0o600); err != nil {
		t.Fatalf("create child exit pipe: %v", err)
	}
	// Hold both ends open so the first child can wait at the exit gate and
	// the release byte remains available even if it has not opened the FIFO.
	exitGate, err := os.OpenFile(exitPipe, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open child exit pipe: %v", err)
	}
	defer func() { _ = exitGate.Close() }()
	messageLog := filepath.Join(dir, "stdio-messages.log")
	invocationLog := filepath.Join(dir, "stdio-invocations.log")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	childStarts := make(chan struct {
		pid int
		err error
	}, 2)
	startupReaderDone := make(chan struct{})
	go func() {
		defer close(startupReaderDone)
		for range 2 {
			if ctx.Err() != nil {
				return
			}
			pipe, err := os.Open(startupPipe)
			if err != nil {
				childStarts <- struct {
					pid int
					err error
				}{err: err}
				return
			}
			line, readErr := bufio.NewReader(pipe).ReadString('\n')
			closeErr := pipe.Close()
			if readErr != nil {
				childStarts <- struct {
					pid int
					err error
				}{err: readErr}
				return
			}
			if closeErr != nil {
				childStarts <- struct {
					pid int
					err error
				}{err: closeErr}
				return
			}
			pid, err := strconv.Atoi(strings.TrimSpace(line))
			if ctx.Err() != nil {
				return
			}
			childStarts <- struct {
				pid int
				err error
			}{pid: pid, err: err}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		// A failed restart can leave the reader waiting in open(2). Opening
		// the FIFO's write side wakes it so the goroutine can observe ctx.
		unblock, err := os.OpenFile(startupPipe, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err == nil {
			_, _ = unblock.WriteString("0\n")
			_ = unblock.Close()
		}
		select {
		case <-startupReaderDone:
		case <-time.After(time.Second):
			t.Errorf("child startup reader did not stop after cleanup")
		}
	})

	firstResponsePosted := make(chan struct{})
	replacementReady := make(chan struct{})
	firstTool := stdioRestartToolCommand(t, "first-tool", "first")
	firstTool.ExpectedResponses[0].PostProcess = func(mocktunnelservice.ReceivedResponse, mocktunnelservice.SharedStorage) {
		close(firstResponsePosted)
	}
	beforeInitialize := stdioGuardToolCommand(t, "replacement-before-initialize", false, http.StatusConflict)
	beforeInitialize.DeliverAfter = replacementReady
	commands := []mocktunnelservice.CommandResponse{
		stdioGuardInitializeCommand(t),
		stdioGuardInitializedCommand(t),
		firstTool,
		beforeInitialize,
		stdioGuardInitializeCommand(t),
		stdioGuardToolCommand(t, "replacement-before-initialized", false, http.StatusConflict),
		stdioGuardInitializedCommand(t),
		stdioRestartToolCommand(t, "second-tool", "second"),
	}

	nextPID := func() int {
		t.Helper()
		select {
		case started := <-childStarts:
			if started.err != nil {
				t.Fatalf("read child startup PID: %v", started.err)
			}
			return started.pid
		case <-ctx.Done():
			t.Fatalf("wait for child startup PID: %v", ctx.Err())
			return 0
		}
	}
	commandArgs := append([]string{
		"env",
		"MOCK_MCP_REQUIRE_INITIALIZED=1",
		"MOCK_MCP_EXIT_AFTER_RESPONSE_NAME=first",
		"MOCK_MCP_EXIT_GATE_PIPE=" + exitPipe,
		"MOCK_MCP_STARTUP_PIPE=" + startupPipe,
		"MOCK_MCP_MESSAGE_LOG=" + messageLog,
		"MOCK_MCP_INVOCATION_LOG=" + invocationLog,
	}, mockmcpserver.StdioServerCommand(t)...)
	h := harnesspkg.NewHarness(t,
		harnesspkg.WithMCPCommand(commandArgs),
		harnesspkg.WithScenarioTimeout(10*time.Second),
		harnesspkg.WithControlPlaneOptions(mocktunnelservice.WithCommandResponses(commands...)),
		harnesspkg.WithAfterClientStart(func(h *harnesspkg.Harness) {
			select {
			case <-firstResponsePosted:
			case <-ctx.Done():
				t.Fatalf("wait for first tool response: %v", ctx.Err())
			}
			if _, err := exitGate.WriteString("exit\n"); err != nil {
				t.Fatalf("release first child after posted tool response: %v", err)
			}
			firstPID, secondPID := nextPID(), nextPID()
			if firstPID == secondPID {
				t.Fatalf("stdio child was not replaced: PID %d", firstPID)
			}
			client := h.PrimaryClient()
			if client == nil {
				t.Fatal("missing tunnel-client instance")
			}
			pollsAfterRestart := client.PollCount()
			if err := client.WaitForPolls(ctx, pollsAfterRestart+1); err != nil {
				t.Fatalf("same tunnel-client did not continue polling after child restart: %v", err)
			}
			close(replacementReady)
		}),
	)
	h.ExecuteScenarious(t)

	messages, err := os.ReadFile(messageLog)
	if err != nil {
		t.Fatalf("read stdio message log: %v", err)
	}
	if got, want := string(messages), "initialize\nnotifications/initialized\ntools/call\ninitialize\nnotifications/initialized\ntools/call\n"; got != want {
		t.Fatalf("stdio messages across both children = %q, want %q", got, want)
	}
	invocations, err := os.ReadFile(invocationLog)
	if err != nil {
		t.Fatalf("read stdio invocation log: %v", err)
	}
	if got, want := string(invocations), "first-tool\nsecond-tool\n"; got != want {
		t.Fatalf("tool invocations (including possible replay) = %q, want %q", got, want)
	}
	if got := len(h.ControlPlane.ReceivedResponses(mocktunnelservice.ResponseMatchMatched)); got != len(commands) {
		t.Fatalf("posted responses = %d, want %d", got, len(commands))
	}
	if got := len(h.ControlPlane.DeliveredCommands()); got != len(commands) {
		t.Fatalf("delivered commands = %d, want %d", got, len(commands))
	}
}

func stdioRestartToolCommand(t *testing.T, requestID, name string) mocktunnelservice.CommandResponse {
	t.Helper()
	rpcID := "tool-" + requestID
	command := stdioGuardCommand(t, requestID, rpcID, json.RawMessage(fmt.Sprintf(`{
		"jsonrpc":"2.0","id":%q,"method":"tools/call",
		"params":{"name":"echo","arguments":{"name":%q,"request_id":%q}}
	}`, rpcID, name, requestID)), http.StatusOK)
	assertEnvelope := command.ExpectedResponses[0].Assert
	command.ExpectedResponses[0].Assert = func(tb testing.TB, response mocktunnelservice.ReceivedResponse) {
		assertEnvelope(tb, response)
		if !bytes.Contains(response.JSONResponse, []byte(`"message":"hello `+name+`"`)) {
			tb.Fatalf("%s tool response = %s, want hello %s", requestID, response.JSONResponse, name)
		}
	}
	return command
}

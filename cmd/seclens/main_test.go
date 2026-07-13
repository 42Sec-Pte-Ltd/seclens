package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"seclens/internal/assessor"
)

func TestRunJSONLStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	opts := assessor.AssessmentOpts{
		Timeout: 2 * time.Second,
	}

	domains := []string{"example.invalid", "also.invalid"}
	runJSONLStreaming(ctx, domains, opts, 2)
}

func TestBinaryAssessSubcmdJSONL(t *testing.T) {
	root := mustModuleRoot(t)
	bin := filepath.Join(t.TempDir(), "seclens")

	build := exec.Command("go", "build", "-o", bin, "./cmd/seclens")
	build.Dir = root
	if err := build.Run(); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	args := []string{"assess", "--format", "jsonl", "--concurrency", "4"}
	for i := 0; i < 20; i++ {
		args = append(args, fmt.Sprintf("d%d.invalid", i))
	}
	run := exec.Command(bin, args...)
	var out bytes.Buffer
	run.Stdout = &out
	run.Stderr = &out

	err := runWithTimeout(run, 20*time.Second)
	if err == context.DeadlineExceeded {
		t.Fatal("runJSONLStreaming deadlocked or too slow for N=20@conc=4 (killed)")
	}

	s := out.String()
	if strings.Contains(s, "Usage:") || strings.Contains(s, "no valid domains after input gating") {
		t.Fatalf("assess subcmd should reach fastpath, not usage: %s", s)
	}
	lines := strings.Count(s, `"Domain"`)
	if lines != 20 {
		t.Fatalf("expected exactly 20 Domain lines from N=20@4 fastpath (got %d)", lines)
	}
}

func TestBinaryAssessFileSmoke(t *testing.T) {
	root := mustModuleRoot(t)
	bin := filepath.Join(t.TempDir(), "seclens")

	build := exec.Command("go", "build", "-o", bin, "./cmd/seclens")
	build.Dir = root
	if err := build.Run(); err != nil {
		t.Fatalf("build failed: %v", err)
	}

	slice := filepath.Join(t.TempDir(), "slice.txt")
	var content strings.Builder
	for i := 0; i < 20; i++ {
		content.WriteString(fmt.Sprintf("dfile%d.invalid\n", i))
	}
	if err := os.WriteFile(slice, []byte(content.String()), 0644); err != nil {
		t.Fatal(err)
	}

	run := exec.Command(bin, "assess", "--file", slice, "--concurrency", "4", "--format", "jsonl")
	var out bytes.Buffer
	run.Stdout = &out
	run.Stderr = &out

	err := runWithTimeout(run, 20*time.Second)
	if err == context.DeadlineExceeded {
		t.Fatal("runJSONLStreaming deadlocked on --file N=20@4")
	}

	s := out.String()
	if strings.Contains(s, "Usage:") {
		t.Fatalf("file smoke hit usage: %s", s)
	}
	lines := strings.Count(s, `"Domain"`)
	if lines != 20 {
		t.Fatalf("expected 20 lines from --file N=20@4 (got %d)", lines)
	}
}

func mustModuleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}").Output()
	if err != nil {
		t.Fatalf("go list -m failed: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func runWithTimeout(cmd *exec.Cmd, d time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Run() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return context.DeadlineExceeded
	}
}
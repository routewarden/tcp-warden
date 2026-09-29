package core

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// LogWriter writes SecurityEvents as single-line JSON entries (JSONL)
// to stdout (for Docker container logs and RouteWarden dashboard streaming)
// as well as the configured log file (for persistent logging and CrowdSec).
type LogWriter struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	stdout io.Writer
}

// NewLogWriter opens or creates the target log file.
func NewLogWriter(path string) (*LogWriter, error) {
	if path == "" {
		return &LogWriter{stdout: os.Stdout}, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return &LogWriter{stdout: os.Stdout}, fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return &LogWriter{stdout: os.Stdout}, fmt.Errorf("opening log file %s: %w", path, err)
	}

	return &LogWriter{file: f, path: path, stdout: os.Stdout}, nil
}

// SetOutput redirects the stdout stream (useful for testing).
func (w *LogWriter) SetOutput(out io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stdout = out
}

// Write appends an event as JSON line to stdout and file.
func (w *LogWriter) Write(ev SecurityEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	// Always output to stdout so Docker captures container logs for 'docker logs'
	// and the RouteWarden dashboard can tail security events.
	out := w.stdout
	if out == nil {
		out = os.Stdout
	}
	_, _ = out.Write(data)

	if w.file != nil {
		_, err = w.file.Write(data)
		return err
	}
	return nil
}

// Close closes the underlying file handle.
func (w *LogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		err := w.file.Close()
		w.file = nil
		return err
	}
	return nil
}

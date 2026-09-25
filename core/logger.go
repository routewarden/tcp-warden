package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LogWriter writes SecurityEvents as single-line JSON entries (JSONL)
// for CrowdSec, SIEM, and RouteWarden dashboard ingestion.
type LogWriter struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// NewLogWriter opens or creates the target log file.
func NewLogWriter(path string) (*LogWriter, error) {
	if path == "" {
		return &LogWriter{}, nil
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating log directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("opening log file %s: %w", path, err)
	}

	return &LogWriter{file: f, path: path}, nil
}

// Write appends an event as JSON line.
func (w *LogWriter) Write(ev SecurityEvent) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.file.Write(data)
	return err
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

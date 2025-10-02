package dashboard

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sync"
)

// OutputCapture captures stdout and stderr for dashboard publishing
type OutputCapture struct {
	buffer       *bytes.Buffer
	originalOut  io.Writer
	originalErr  io.Writer
	mutex        sync.Mutex
	publisher    *Publisher
}

// NewOutputCapture creates a new output capture instance
func NewOutputCapture(publisher *Publisher) *OutputCapture {
	return &OutputCapture{
		buffer:      &bytes.Buffer{},
		originalOut: os.Stdout,
		originalErr: os.Stderr,
		publisher:   publisher,
	}
}

// Start begins capturing output
func (oc *OutputCapture) Start() {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	
	// Create new file descriptors for capturing
	// Note: This is a simplified implementation
	// In production, you might want to use more sophisticated capture mechanisms
}

// Stop restores original output streams and returns captured content
func (oc *OutputCapture) Stop() string {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	
	// In this simplified version, just return buffer contents
	return oc.buffer.String()
}

// GetOutput returns the current captured output
func (oc *OutputCapture) GetOutput() string {
	oc.mutex.Lock()
	defer oc.mutex.Unlock()
	return oc.buffer.String()
}

type writerWrapper struct {
	original  io.Writer
	buffer    *bytes.Buffer
	publisher *Publisher
}

func (w *writerWrapper) Write(p []byte) (n int, err error) {
	// Write to original output (console)
	n, err = w.original.Write(p)
	if err != nil {
		return n, err
	}
	
	// Also write to buffer for dashboard
	w.buffer.Write(p)
	
	// Update publisher with current output
	if w.publisher != nil {
		w.publisher.UpdateOutput(w.buffer.String())
	}
	
	return n, nil
}

// CaptureFunction executes a function while capturing its output
func CaptureFunction(publisher *Publisher, fn func() error) (string, error) {
	if publisher == nil {
		return "", fn()
	}
	
	capture := NewOutputCapture(publisher)
	capture.Start()
	defer func() {
		output := capture.Stop()
		if err := fn(); err != nil {
			publisher.Error(err.Error(), output, 1)
		} else {
			publisher.Complete(output, 0)
		}
	}()
	
	return capture.GetOutput(), fn()
}

// Printf is a dashboard-aware printf function
func Printf(publisher *Publisher, format string, args ...interface{}) {
	output := fmt.Sprintf(format, args...)
	fmt.Print(output)
	
	if publisher != nil {
		// Update the publisher with current output
		// This is a simple approach - in production you might want to accumulate output
		publisher.UpdateOutput(output)
	}
}

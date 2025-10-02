package dashboard

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// CommandWrapper wraps command execution with dashboard publishing
type CommandWrapper struct {
	publisher *Publisher
	buffer    *bytes.Buffer
}

// NewCommandWrapper creates a new command wrapper
func NewCommandWrapper(cmd *cobra.Command, module string, cmdName string, args []string) *CommandWrapper {
	dashboardFlag, _ := cmd.Flags().GetBool("dashboard")
	if !dashboardFlag {
		return &CommandWrapper{}
	}

	// Collect flag values
	flagValues := make(map[string]interface{})
	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		flagValues[f.Name] = f.Value.String()
	})

	publisher := CreateCommandPublisher(module, cmdName, args, flagValues)
	publisher.Start()

	return &CommandWrapper{
		publisher: publisher,
		buffer:    &bytes.Buffer{},
	}
}

// Execute wraps the execution of a function with dashboard publishing
func (cw *CommandWrapper) Execute(fn func() error) error {
	if cw.publisher == nil {
		return fn()
	}

	// Capture output
	oldStdout := os.Stdout
	oldStderr := os.Stderr
	
	r, w, _ := os.Pipe()
	os.Stdout = w
	os.Stderr = w

	// Start copying output
	done := make(chan bool)
	go func() {
		io.Copy(cw.buffer, r)
		done <- true
	}()

	// Execute the function
	err := fn()

	// Restore output
	w.Close()
	os.Stdout = oldStdout
	os.Stderr = oldStderr

	// Wait for copy to complete
	<-done

	// Write captured output to original stdout
	output := cw.buffer.String()
	fmt.Print(output)

	// Publish result
	if err != nil {
		cw.publisher.Error(err.Error(), output, 1)
	} else {
		cw.publisher.Complete(output, 0)
	}

	return err
}

// IsEnabled returns whether dashboard publishing is enabled
func (cw *CommandWrapper) IsEnabled() bool {
	return cw.publisher != nil
}

// Printf provides dashboard-aware printing
func (cw *CommandWrapper) Printf(format string, args ...interface{}) {
	output := fmt.Sprintf(format, args...)
	fmt.Print(output)
	
	if cw.publisher != nil {
		cw.buffer.WriteString(output)
		cw.publisher.UpdateOutput(cw.buffer.String())
	}
}

// Println provides dashboard-aware printing
func (cw *CommandWrapper) Println(args ...interface{}) {
	output := fmt.Sprintln(args...)
	fmt.Print(output)
	
	if cw.publisher != nil {
		cw.buffer.WriteString(output)
		cw.publisher.UpdateOutput(cw.buffer.String())
	}
}

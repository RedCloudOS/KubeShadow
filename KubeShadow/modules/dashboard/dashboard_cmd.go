package dashboard_cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"kubeshadow/pkg/dashboard"

	"github.com/spf13/cobra"
)

var DashboardCmd = &cobra.Command{
	Use:   "dashboard",
	Short: "Start the KubeShadow web dashboard",
	Long:  "Start the web dashboard to monitor KubeShadow command executions in real-time",
	RunE: func(cmd *cobra.Command, args []string) error {
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			return fmt.Errorf("failed to get port flag: %w", err)
		}

		dashboardInstance := dashboard.GetInstance()
		
		if err := dashboardInstance.Start(port); err != nil {
			return fmt.Errorf("failed to start dashboard: %w", err)
		}

		fmt.Printf("🎯 KubeShadow Dashboard started on http://localhost:%d\n", port)
		fmt.Println("📊 Use the --dashboard flag with other commands to publish results here")
		fmt.Println("Press Ctrl+C to stop the dashboard")

		// Wait for interrupt signal
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c

		fmt.Println("\nShutting down dashboard...")
		return dashboardInstance.Stop()
	},
}

func init() {
	DashboardCmd.Flags().Int("port", 8080, "Port for the dashboard web server")
}

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func sonarqubeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sonarqube",
		Short: "SonarQube plugin commands",
	}
	cmd.AddCommand(sonarqubeParseCmd())
	cmd.AddCommand(sonarqubeScoreCmd())
	return cmd
}

func sonarqubeParseCmd() *cobra.Command {
	return parseCmd("sonarqube")
}

func sonarqubeScoreCmd() *cobra.Command {
	var scoreReportPath string
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Calculate score for SonarQube across all services",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := calculateOverallScore("sonarqube")
			if err != nil {
				return err
			}
			if scoreReportPath != "" {
				err = os.WriteFile(scoreReportPath, []byte(output), 0644)
				if err != nil {
					return fmt.Errorf("failed to write to file: %w", err)
				}
			} else {
				fmt.Println(output)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&scoreReportPath, "report-path", "", "Path to save the score report (optional)")
	return cmd
}

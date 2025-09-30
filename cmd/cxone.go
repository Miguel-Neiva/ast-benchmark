package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func cxoneCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cxone",
		Short: "CxOne plugin commands",
	}
	cmd.AddCommand(cxoneParseCmd())
	cmd.AddCommand(cxoneScoreCmd())
	return cmd
}

func cxoneParseCmd() *cobra.Command {
	return parseCmd("cxone")
}

func cxoneScoreCmd() *cobra.Command {
	var scoreReportPath string
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Calculate score for CxOne across all services",
		RunE: func(cmd *cobra.Command, args []string) error {
			output, err := calculateOverallScore("cxone")
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

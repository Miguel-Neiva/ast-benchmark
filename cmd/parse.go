package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/model"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func parseCmd(pluginName string) *cobra.Command {
	return &cobra.Command{
		Use:   "parse",
		Short: fmt.Sprintf("Parse the %s report", pluginName),
		RunE: func(cmd *cobra.Command, args []string) error {
			if filePath == "" {
				return fmt.Errorf("report path is required")
			}
			if _, err := os.Stat(filePath); os.IsNotExist(err) {
				return fmt.Errorf("report file does not exist at path: %s", filePath)
			}

			results, err := GetResults(filePath, pluginName)
			if err != nil {
				return fmt.Errorf("failed to process report: %w", err)
			}
			jsonData, err := model.ExpectedReportToJson(results)
			if err != nil {
				return fmt.Errorf("failed to convert report to JSON: %w", err)
			}
			if reportPath == "" {
				return fmt.Errorf("report path is required (use --report-path)")
			}
			if err := os.MkdirAll(filepath.Dir(reportPath), 0755); err != nil {
				return fmt.Errorf("failed to create directory for report: %w", err)
			}
			if err := os.WriteFile(reportPath, jsonData, 0644); err != nil {
				return fmt.Errorf("failed to write JSON to file: %w", err)
			}
			log.Info().Str("output", reportPath).Msg(fmt.Sprintf("Normalized %s report saved successfully.", pluginName))
			return nil
		},
	}
}

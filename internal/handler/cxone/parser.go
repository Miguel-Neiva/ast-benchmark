package cxone

import (
	"encoding/json"
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/cx-miguel-neiva/ast-benchmark/plugins"
	"github.com/rs/zerolog/log"
)

// Map of standardized CWEs (inspired by OWASP Benchmark)
// Centralized for use by all CxOne parsers
var cweMappings = map[string]string{
	// Data Exposure
	"CWE-200": "CWE-668", // Information Exposure -> Exposure of Resource to Wrong Sphere
	"CWE-668": "CWE-668", // Already standardized

	// Command Injection
	"CWE-77": "CWE-77", // Command Injection
	"CWE-15": "CWE-77", // Command Injection (mapped to 77)

	// Path Traversal
	"CWE-36": "CWE-22", // Path Traversal
	"CWE-23": "CWE-22", // Path Traversal (mapped to 22)

	// Weak Randomness
	"CWE-338": "CWE-338", // Weak Randomness

	// Add more as needed based on reports
}

// StandardizeCWE standardizes CWE IDs for consistency across tools
// Returns the standardized CWE or the original if no mapping exists
func StandardizeCWE(cwe string) string {
	if standard, exists := cweMappings[cwe]; exists {
		return standard
	}
	return cwe // Return original if no mapping exists
}

func ParseReport(item plugins.ISourceItem) (map[string][]handler.EngineResult, error) {
	content := item.GetContent()
	if content == nil {
		err := fmt.Errorf("item %s contains empty content", item.GetID())
		log.Error().Err(err).Msg("Error processing item")
		return nil, err
	}

	contentBytes := []byte(*content)
	var raw map[string]interface{}
	if err := json.Unmarshal(contentBytes, &raw); err != nil {
		return nil, err
	}

	raw["engine"] = "cxone"

	header, ok := raw["reportHeader"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing or invalid reportHeader")
	}
	projectName, _ := header["projectName"].(string)

	resultMap := make(map[string][]handler.EngineResult)

	if iac, ok := raw["iacScanResults"]; ok {
		if arr, ok := iac.(map[string]interface{})["technology"].([]interface{}); ok && len(arr) > 0 {
			if result, err := parseIac(iac); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing IAC results")
			}
		}
	}

	if sca, ok := raw["scaScanResults"]; ok {
		if arr, ok := sca.(map[string]interface{})["packages"].([]interface{}); ok && len(arr) > 0 {
			if result, err := parseSca(sca); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing SCA results")
			}
		}
	}

	if scs, ok := raw["scsScanResults"]; ok {
		if arr, ok := scs.(map[string]interface{})["resultsList"].([]interface{}); ok && len(arr) > 0 {
			if result, err := parseScs(scs); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing SCS results")
			}
		}
	}

	if sast, ok := raw["scanResults"]; ok {
		if resultsList, ok := sast.(map[string]interface{})["resultsList"].([]interface{}); ok && len(resultsList) > 0 {
			if result, err := parseSast(sast); err == nil {
				resultMap[projectName] = append(resultMap[projectName], result)
			} else {
				log.Warn().Err(err).Msg("Error processing SAST results")
			}
		}
	}

	return resultMap, nil
}

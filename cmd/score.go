package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

func calculateOverallScore(plugin string) (string, error) {
	benchmarksDir := "benchmarks"
	services := findServicePaths(benchmarksDir)

	results := make(map[string]interface{})
	for _, servicePath := range services {
		score, err := calculateServiceScore(servicePath, plugin)
		if err != nil {
			// Skip if error, e.g., no expected or vulnerable
			continue
		}
		// Use the service name as key, e.g., mad-deployment-service
		serviceName := filepath.Base(servicePath)
		results[serviceName] = score
	}

	output, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}
	return string(output), nil
}

func findServicePaths(benchmarksDir string) []string {
	var services []string
	filepath.Walk(benchmarksDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.Name() == "expected.json" {
			servicePath := filepath.Dir(path)
			services = append(services, servicePath)
		}
		return nil
	})
	return services
}

func calculateServiceScore(servicePath, plugin string) (map[string]interface{}, error) {
	// Load expected.json
	expectedPath := filepath.Join(servicePath, "expected.json")
	expectedContent, err := os.ReadFile(expectedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read expected.json: %w", err)
	}

	var expected []struct {
		ProjectName string                 `json:"projectName"`
		Results     []handler.EngineResult `json:"results"`
	}
	if err := json.Unmarshal(expectedContent, &expected); err != nil {
		return nil, fmt.Errorf("failed to unmarshal expected.json: %w", err)
	}

	// Load vulnerable.json
	vulnerablePath := filepath.Join(servicePath, "plugins", plugin, "vulnerable.json")
	vulnerableContent, err := os.ReadFile(vulnerablePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read vulnerable.json for plugin %s: %w", plugin, err)
	}

	var vulnerable []struct {
		ProjectName string                 `json:"projectName"`
		Results     []handler.EngineResult `json:"results"`
	}
	if err := json.Unmarshal(vulnerableContent, &vulnerable); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vulnerable.json: %w", err)
	}

	// Assume single project
	if len(expected) == 0 || len(vulnerable) == 0 {
		return nil, fmt.Errorf("empty expected or vulnerable data")
	}
	exp := expected[0]
	vuln := vulnerable[0]

	// Prepare engines map
	engines := make(map[string]map[string]int)
	overallTotal := 0
	for _, eRes := range exp.Results {
		engine := eRes.EngineType
		if _, ok := engines[engine]; !ok {
			engines[engine] = map[string]int{"tp": 0, "total": 0}
		}
		engines[engine]["total"] += len(eRes.Details)
		overallTotal += len(eRes.Details)
	}

	// Calculate tp
	overallTp := 0
	for _, vRes := range vuln.Results {
		engine := vRes.EngineType
		if _, ok := engines[engine]; !ok {
			continue
		}
		for _, vDet := range vRes.Details {
			for _, eRes := range exp.Results {
				if eRes.EngineType == engine {
					for _, eDet := range eRes.Details {
						if eDet.ResultID == vDet.ResultID {
							engines[engine]["tp"]++
							overallTp++
							goto nextVDet
						}
					}
				}
			}
		nextVDet:
		}
	}

	// Build result
	result := map[string]interface{}{
		"plugin": plugin,
		"overall": map[string]interface{}{
			"tpPercentage": 0.0,
			"detected":     overallTp,
			"total":        overallTotal,
		},
		"engines": make(map[string]interface{}),
	}
	if overallTotal > 0 {
		result["overall"].(map[string]interface{})["tpPercentage"] = float64(overallTp) / float64(overallTotal) * 100
	}
	for eng, counts := range engines {
		tp := counts["tp"]
		total := counts["total"]
		engResult := map[string]interface{}{
			"tpPercentage": 0.0,
			"detected":     tp,
			"total":        total,
		}
		if total > 0 {
			engResult["tpPercentage"] = float64(tp) / float64(total) * 100
		}
		result["engines"].(map[string]interface{})[eng] = engResult
	}

	return result, nil
}

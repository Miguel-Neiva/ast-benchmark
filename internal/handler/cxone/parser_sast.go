package cxone

import (
	"fmt"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

// Simple map of CWE-based descriptions
var cweDescriptions = map[string]string{
	"CWE-250": "Execution with Unnecessary Privileges",
	"CWE-710": "Coding Standards Violation",
	"CWE-668": "Exposure of Resource to Wrong Sphere",
	"CWE-284": "Improper Access Control",
	"CWE-400": "Uncontrolled Resource Consumption",
}

func parseSast(data interface{}) (handler.EngineResult, error) {
	sastMap, ok := data.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("invalid SAST data format")
	}

	resultsList, ok := sastMap["resultsList"].([]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("missing or invalid resultsList")
	}

	var details []handler.VulnerabilityDetail
	for _, resultRaw := range resultsList {
		result, ok := resultRaw.(map[string]interface{})
		if !ok {
			continue
		}

		queryPath := handler.ToStr(result["queryPath"])
		cweId := handler.ToStr(result["cweId"])

		if queryPath == "" || cweId == "" {
			continue
		}

		// Extract query name from path (last part after /)
		queryName := queryPath
		if idx := strings.LastIndex(queryPath, "/"); idx != -1 {
			queryName = queryPath[idx+1:]
		}

		// Simple description
		vulnValue := cweId

		// Apply CWE mapping for standardization
		vulnValue = standardizeCWE(vulnValue)

		resourceType := "FileName"
		vulnID := handler.GenerateResultID(resourceType, queryPath, queryName, vulnValue)

		details = append(details, handler.VulnerabilityDetail{
			ResultID:              vulnID,
			ResourceType:          resourceType,
			Resource:              queryPath,
			VulnerabilityCategory: queryName,
			VulnerabilityValue:    vulnValue,
		})
	}

	return handler.EngineResult{
		EngineType: "SAST",
		Details:    details,
	}, nil
}

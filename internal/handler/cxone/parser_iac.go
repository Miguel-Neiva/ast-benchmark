package cxone

import (
	"fmt"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
)

// Simple map of CWE-based descriptions
var cweDescriptionsIAC = map[string]string{
	"CWE-250": "Execution with Unnecessary Privileges",
	"CWE-710": "Coding Standards Violation",
	"CWE-668": "Exposure of Resource to Wrong Sphere",
	"CWE-284": "Improper Access Control",
	"CWE-400": "Uncontrolled Resource Consumption",
}

// standardizeCWE standardizes CWE IDs for consistency across tools
func standardizeCWE(cwe string) string {
	if standard, exists := cweMappings[cwe]; exists {
		return standard
	}
	return cwe // Return original if no mapping exists
}

// mapCWEToStandard normalizes CWE IDs from CxOne to the desired standard
// This allows different tools to report the same vulnerability with different CWE IDs
// but we normalize them for consistency in the ground truth
func mapCWEToStandard(cweId string) string {
	cweMap := map[string]string{
		// CxOne-specific mappings to standard CWE
		// Examples of possible mappings:
		// "CWE-123": "CWE-124", // If CxOne reports CWE-123 but we want to use CWE-124 as standard
		// "CWE-200": "CWE-668", // If CxOne reports CWE-200 but we want to use CWE-668 (Exposure of Resource)

		// Mappings based on CxOne report analysis
		// Add as needed based on real report analysis
	}

	if standardCWE, exists := cweMap[cweId]; exists {
		return standardCWE
	}

	// Return the original CWE if no specific mapping exists
	return cweId
}

// addCWEMapping allows adding new CWE mappings at runtime
// Useful for dynamic configurations based on report analysis
func addCWEMapping(fromCWE, toCWE string) {
	// Note: This is a simplified implementation
	// In production, this could be stored in a database or configuration file
	// For now, mappings are hardcoded in the mapCWEToStandard function
}

func parseIac(iacData interface{}) (handler.EngineResult, error) {
	data, ok := iacData.(map[string]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("invalid IAC structure")
	}
	techs, ok := data["technology"].([]interface{})
	if !ok {
		return handler.EngineResult{}, fmt.Errorf("missing or invalid IAC technologies")
	}

	var details []handler.VulnerabilityDetail
	for _, techRaw := range techs {
		tech, _ := techRaw.(map[string]interface{})
		queries, _ := tech["queries"].([]interface{})
		for _, queryRaw := range queries {
			query, _ := queryRaw.(map[string]interface{})
			queryName, _ := query["queryName"].(string)
			resultsList, _ := query["resultsList"].([]interface{})
			for _, res := range resultsList {
				r, _ := res.(map[string]interface{})
				resourceType := "Filename"
				resource := handler.ToStr(r["fileName"])
				cweId := getCWEFromQueryName(queryName)
				// Apply CWE mapping for standardization
				cweId = standardizeCWE(cweId)
				vulnValue := cweId
				resultID := handler.GenerateResultID(resourceType, resource, queryName, vulnValue)

				details = append(details, handler.VulnerabilityDetail{
					ResultID:              resultID,
					ResourceType:          resourceType,
					Resource:              resource,
					VulnerabilityCategory: queryName,
					VulnerabilityValue:    vulnValue,
				})
			}
		}
	}

	return handler.EngineResult{EngineType: "IAC", Details: details}, nil
}

func getCWEFromQueryName(queryName string) string {
	switch queryName {
	case "Privilege Escalation Allowed":
		return "CWE-250"
	case "Using Unrecommended Namespace":
		return "CWE-710"
	case "Service Account Token Automount Not Disabled":
		return "CWE-668"
	case "Seccomp Profile Is Not Configured":
		return "CWE-284"
	case "Readiness Probe Is Not Configured":
		return "CWE-400"
	case "NET_RAW Capabilities Not Being Dropped":
		return "CWE-250"
	case "Memory Requests Not Defined":
		return "CWE-400"
	case "Memory Limits Not Defined":
		return "CWE-400"
	case "Container Running With Low UID":
		return "CWE-250"
	case "Container Running As Root":
		return "CWE-250"
	case "Volume Mount With OS Directory Write Permissions":
		return "CWE-668"
	case "MinIO Bucket Public ACL":
		return "CWE-668"
	default:
		return "CWE-710" // Generic
	}
}

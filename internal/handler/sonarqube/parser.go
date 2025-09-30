package sonarqube

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cx-miguel-neiva/ast-benchmark/internal/handler"
	"github.com/cx-miguel-neiva/ast-benchmark/plugins"
)

// ParseReport converts a SonarQube issues export into the internal normalized format.
// It attempts to classify each issue into one of the benchmark "engines": SAST, SCA, IAC.
// Heuristics (can be refined later):
//
//	IAC if rule prefix or file suggest infrastructure (docker, terraform, kubernetes, helm, yaml with k8s manifests)
//	SCA if file is a dependency manifest (package.json, go.mod, pom.xml, requirements.txt, build.gradle, yarn.lock)
//	Otherwise SAST.
//
// Fields mapping:
//
//	ResourceType: matches existing engine conventions (FileName for SAST, Filename for IAC, Package for SCA)
//	VulnerabilityCategory: "CWE" (mapped from SonarQube rules)
//	VulnerabilityValue: CWE ID (mapped from rule)
//	ResultID: sha256 hash of (resourceType|resource|category|value) - same scheme as other parsers.
func ParseReport(item plugins.ISourceItem) (map[string][]handler.EngineResult, error) {
	content := item.GetContent()
	if content == nil {
		return nil, fmt.Errorf("empty content for item %s", item.GetID())
	}

	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(*content), &raw); err != nil {
		return nil, fmt.Errorf("invalid json: %w", err)
	}

	issuesAny, _ := raw["issues"].([]interface{})
	compsAny, _ := raw["components"].([]interface{})

	// Build component metadata maps
	componentPath := map[string]string{}
	componentQualifier := map[string]string{}
	for _, c := range compsAny {
		m, _ := c.(map[string]interface{})
		key := handler.ToStr(m["key"])
		if key == "" {
			continue
		}
		if p := handler.ToStr(m["path"]); p != "" {
			componentPath[key] = p
		}
		if q := handler.ToStr(m["qualifier"]); q != "" {
			componentQualifier[key] = q
		}
	}

	// Determine project name by TRK qualifier first; fallback to first component before ':'
	projectName := "sonarqube-project"
	for k, q := range componentQualifier {
		if q == "TRK" { // Sonar's Track qualifier
			projectName = k
			break
		}
	}
	if projectName == "sonarqube-project" { // fallback
		for k := range componentPath {
			if idx := strings.IndexByte(k, ':'); idx == -1 { // no file separator part
				projectName = k
				break
			}
		}
	}

	// Prepare per-engine buckets
	buckets := map[string][]handler.VulnerabilityDetail{
		"SAST": {},
		"SCA":  {},
		"IAC":  {},
	}

	seen := map[string]struct{}{}

	for _, is := range issuesAny {
		issue, _ := is.(map[string]interface{})
		if issue == nil {
			continue
		}
		rule := handler.ToStr(issue["rule"])
		component := handler.ToStr(issue["component"])
		issueType := handler.ToStr(issue["type"]) // CODE_SMELL, VULNERABILITY, SECURITY_HOTSPOT
		if rule == "" || component == "" {
			continue
		}

		// Derive file path
		resourcePath := componentPath[component]
		if resourcePath == "" {
			// component format often projectKey:path
			if idx := strings.Index(component, ":"); idx != -1 && idx+1 < len(component) {
				resourcePath = component[idx+1:]
			} else {
				resourcePath = component
			}
		}

		engineType := classifyEngine(rule, issueType, resourcePath)
		var resourceType string
		var vulnCategory string
		var vulnValue string
		var resource string

		// Map SonarQube rule to CWE
		cweValue := mapRuleToCWE(rule)

		switch engineType {
		case "IAC":
			resourceType = "Filename" // matches existing IAC parser
			resource = resourcePath   // Keep full path for IAC
			vulnCategory = rule
			vulnValue = cweValue
		case "SCA":
			resourceType = "Package"
			// Use manifest filename as resource
			resource = filepath.Base(resourcePath)
			vulnCategory = rule
			vulnValue = cweValue
		default: // SAST
			resourceType = "FileName" // matches existing SAST parser
			resource = resourcePath
			vulnCategory = rule
			vulnValue = cweValue
		}

		id := handler.GenerateResultID(resourceType, resource, vulnCategory, vulnValue)
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}

		buckets[engineType] = append(buckets[engineType], handler.VulnerabilityDetail{
			ResultID:              id,
			ResourceType:          resourceType,
			Resource:              resource,
			VulnerabilityCategory: vulnCategory,
			VulnerabilityValue:    vulnValue,
		})
	}

	// Build final engine results (only non-empty)
	var engineResults []handler.EngineResult
	for eng, dets := range buckets {
		if len(dets) == 0 {
			continue
		}
		engineResults = append(engineResults, handler.EngineResult{EngineType: eng, Details: dets})
	}

	return map[string][]handler.EngineResult{projectName: engineResults}, nil
}

// classifyEngine returns one of SAST, SCA, IAC based on heuristics.
func classifyEngine(rule, issueType, path string) string {
	rLower := strings.ToLower(rule)
	pLower := strings.ToLower(path)

	// IAC indicators
	if strings.HasPrefix(rLower, "docker:") || strings.Contains(pLower, "dockerfile") ||
		strings.Contains(pLower, ".tf") || strings.Contains(rLower, "terraform") ||
		strings.Contains(pLower, "k8s") || strings.Contains(pLower, "kubernetes") ||
		strings.Contains(pLower, "helm") || strings.HasSuffix(pLower, ".yaml") || strings.HasSuffix(pLower, ".yml") && (strings.Contains(pLower, "deploy") || strings.Contains(pLower, "chart")) {
		return "IAC"
	}

	// SCA indicators (dependency manifests)
	if strings.HasSuffix(pLower, "package.json") || strings.HasSuffix(pLower, "go.mod") ||
		strings.HasSuffix(pLower, "go.sum") || strings.HasSuffix(pLower, "pom.xml") ||
		strings.HasSuffix(pLower, "build.gradle") || strings.HasSuffix(pLower, "requirements.txt") ||
		strings.HasSuffix(pLower, "yarn.lock") {
		return "SCA"
	}
	if strings.Contains(rLower, "dependency") || strings.Contains(rLower, "sca") {
		return "SCA"
	}

	// Default SAST (code rules, security hotspots, vulnerabilities)
	_ = issueType // reserved for future refinements
	return "SAST"
}

// mapRuleToCWE maps SonarQube rules to CWE IDs for better comparison with expected.json
func mapRuleToCWE(rule string) string {
	ruleMap := map[string]string{
		// Kubernetes rules
		"kubernetes:S6865": "CWE-250", // Bind this resource's automounted service account to RBAC or disable automounting
		"kubernetes:S6873": "CWE-400", // Specify a memory request for this container
		"kubernetes:S6892": "CWE-400", // Specify a CPU request for this container
		"kubernetes:S6897": "CWE-400", // Specify a storage request for this container
		"kubernetes:S6866": "CWE-710", // Using Unrecommended Namespace
		"kubernetes:S6867": "CWE-668", // Service Account Token Automount Not Disabled
		"kubernetes:S6868": "CWE-284", // Seccomp Profile Is Not Configured
		"kubernetes:S6869": "CWE-400", // Readiness Probe Is Not Configured
		"kubernetes:S6870": "CWE-250", // NET_RAW Capabilities Not Being Dropped
		"kubernetes:S6871": "CWE-400", // Memory Requests Not Defined
		"kubernetes:S6872": "CWE-400", // Memory Limits Not Defined
		"kubernetes:S6874": "CWE-250", // Container Running With Low UID
		"kubernetes:S6875": "CWE-250", // Container Running As Root
		"kubernetes:S6876": "CWE-668", // Volume Mount With OS Directory Write Permissions
		// Docker rules
		"docker:S6596": "CWE-710", // Use specific version tag -> Improper Adherence to Coding Standards
		"docker:S6476": "CWE-710", // Uppercase AS -> Improper Adherence to Coding Standards
		"docker:S7020": "CWE-710", // Split RUN instruction -> Improper Adherence to Coding Standards
		// Add more mappings as needed
	}
	if cwe, exists := ruleMap[rule]; exists {
		return cwe
	}
	// Default fallback for unmapped rules
	return "CWE-710" // Generic coding standard issue
}

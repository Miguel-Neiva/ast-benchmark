package handler

// Map of standardized CWEs (inspired by OWASP Benchmark)
// Centralized for use by all parsers
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

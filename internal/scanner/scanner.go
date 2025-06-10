package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nickciolpan/docker-scan-lite/internal/rules"
	"github.com/fatih/color"
)

// Scanner represents a Dockerfile scanner
type Scanner struct {
	dockerfilePath string
	verbose        bool
	rules          *rules.Rules
}

// ScanResult holds the results of the scan
type ScanResult struct {
	Dockerfile     string                `json:"dockerfile"`
	Timestamp      time.Time             `json:"timestamp"`
	BaseImages     []BaseImageInfo       `json:"base_images"`
	ExposedPorts   []string              `json:"exposed_ports"`
	EnvVars        []EnvVarInfo          `json:"env_vars"`
	Secrets        []rules.SecretInfo    `json:"secrets"`
	SecurityIssues []SecurityIssue       `json:"security_issues"`
	Summary        ScanSummary           `json:"summary"`
}

// BaseImageInfo contains information about base images
type BaseImageInfo struct {
	Image      string `json:"image"`
	Tag        string `json:"tag"`
	Line       int    `json:"line"`
	IsOutdated bool   `json:"is_outdated"`
	Severity   string `json:"severity"`
	Reason     string `json:"reason"`
}

// EnvVarInfo contains information about environment variables
type EnvVarInfo struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Line        int    `json:"line"`
	IsSensitive bool   `json:"is_sensitive"`
}

// SecurityIssue represents a security issue found
type SecurityIssue struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Line        int    `json:"line"`
	Instruction string `json:"instruction"`
}

// ScanSummary provides a summary of the scan results
type ScanSummary struct {
	TotalIssues    int `json:"total_issues"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
	InfoSeverity   int `json:"info_severity"`
}

// NewScanner creates a new scanner instance
func NewScanner(dockerfilePath string, verbose bool) *Scanner {
	return &Scanner{
		dockerfilePath: dockerfilePath,
		verbose:        verbose,
		rules:          rules.New(),
	}
}

// Scan analyzes the Dockerfile and returns results
func (s *Scanner) Scan() (*ScanResult, error) {
	file, err := os.Open(s.dockerfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Dockerfile: %v", err)
	}
	defer file.Close()

	result := &ScanResult{
		Dockerfile:     s.dockerfilePath,
		Timestamp:      time.Now(),
		BaseImages:     []BaseImageInfo{},
		ExposedPorts:   []string{},
		EnvVars:        []EnvVarInfo{},
		Secrets:        []rules.SecretInfo{},
		SecurityIssues: []SecurityIssue{},
	}

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	var continuedLine string
	var continuedLineNumber int

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle line continuation
		if strings.HasSuffix(line, "\\") {
			if continuedLine == "" {
				continuedLineNumber = lineNumber
			}
			continuedLine += strings.TrimSuffix(line, "\\") + " "
			continue
		} else {
			if continuedLine != "" {
				// This is the end of a multi-line command
				line = continuedLine + line
				lineNumber = continuedLineNumber
				continuedLine = ""
				continuedLineNumber = 0
			}
		}

		s.analyzeLine(line, lineNumber, result)
	}

	// Handle case where file ends with a continued line
	if continuedLine != "" {
		s.analyzeLine(continuedLine, continuedLineNumber, result)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Dockerfile: %v", err)
	}

	s.calculateSummary(result)
	return result, nil
}

// analyzeLine analyzes a single line of the Dockerfile
func (s *Scanner) analyzeLine(line string, lineNumber int, result *ScanResult) {
	// Parse instruction
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	instruction := strings.ToUpper(parts[0])
	
	switch instruction {
	case "FROM":
		s.analyzeFromInstruction(parts, lineNumber, result)
	case "EXPOSE":
		s.analyzeExposeInstruction(parts, lineNumber, result)
	case "ENV":
		s.analyzeEnvInstruction(parts, lineNumber, result)
	case "RUN":
		s.analyzeRunInstruction(line, lineNumber, result)
	case "ADD", "COPY":
		s.analyzeFileInstruction(line, lineNumber, result)
	case "USER":
		s.analyzeUserInstruction(parts, lineNumber, result)
	}

	// Check for secrets in any instruction
	s.checkForSecrets(line, lineNumber, result)
}

// analyzeFromInstruction analyzes FROM instructions for base image info
func (s *Scanner) analyzeFromInstruction(parts []string, lineNumber int, result *ScanResult) {
	if len(parts) < 2 {
		return
	}

	imageRef := parts[1]
	if strings.Contains(imageRef, " as ") {
		imageRef = strings.Split(imageRef, " as ")[0]
	}

	image, tag := s.parseImageReference(imageRef)
	
	baseImage := BaseImageInfo{
		Image: image,
		Tag:   tag,
		Line:  lineNumber,
	}

	// Check if image is outdated or has known issues
	s.checkBaseImageSecurity(&baseImage)
	
	result.BaseImages = append(result.BaseImages, baseImage)
}

// analyzeExposeInstruction analyzes EXPOSE instructions
func (s *Scanner) analyzeExposeInstruction(parts []string, lineNumber int, result *ScanResult) {
	for i := 1; i < len(parts); i++ {
		port := parts[i]
		result.ExposedPorts = append(result.ExposedPorts, port)
		
		// Check for commonly vulnerable ports
		if s.rules.IsVulnerablePort(port) {
			result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
				Type:        "vulnerable_port",
				Severity:    "medium",
				Description: fmt.Sprintf("Port %s may be vulnerable or should not be exposed", port),
				Line:        lineNumber,
				Instruction: "EXPOSE",
			})
		}
	}
}

// analyzeEnvInstruction analyzes ENV instructions
func (s *Scanner) analyzeEnvInstruction(parts []string, lineNumber int, result *ScanResult) {
	if len(parts) < 3 {
		return
	}

	var name, value string
	if strings.Contains(parts[1], "=") {
		// ENV KEY=value format
		kv := strings.SplitN(parts[1], "=", 2)
		name = kv[0]
		if len(kv) > 1 {
			value = kv[1]
		}
	} else {
		// ENV KEY value format
		name = parts[1]
		if len(parts) > 2 {
			value = strings.Join(parts[2:], " ")
		}
	}

	envVar := EnvVarInfo{
		Name:        name,
		Value:       value,
		Line:        lineNumber,
		IsSensitive: s.rules.IsSensitiveEnvVar(name),
	}

	result.EnvVars = append(result.EnvVars, envVar)

	if envVar.IsSensitive {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "sensitive_env_var",
			Severity:    "high",
			Description: fmt.Sprintf("Sensitive environment variable '%s' found", name),
			Line:        lineNumber,
			Instruction: "ENV",
		})
	}
}

// analyzeRunInstruction analyzes RUN instructions
func (s *Scanner) analyzeRunInstruction(line string, lineNumber int, result *ScanResult) {
	// Check for security issues in RUN commands
	if s.rules.HasInsecureCommand(line) {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "insecure_command",
			Severity:    "medium",
			Description: "Potentially insecure command detected",
			Line:        lineNumber,
			Instruction: "RUN",
		})
	}

	// Check for package manager without version pinning
	if s.rules.HasUnpinnedPackages(line) {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "unpinned_packages",
			Severity:    "low",
			Description: "Package installation without version pinning detected",
			Line:        lineNumber,
			Instruction: "RUN",
		})
	}
}

// analyzeFileInstruction analyzes ADD/COPY instructions
func (s *Scanner) analyzeFileInstruction(line string, lineNumber int, result *ScanResult) {
	if strings.HasPrefix(strings.ToUpper(line), "ADD") && strings.Contains(line, "http") {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "remote_file_add",
			Severity:    "medium",
			Description: "ADD instruction with remote URL detected, consider using COPY instead",
			Line:        lineNumber,
			Instruction: "ADD",
		})
	}
}

// analyzeUserInstruction analyzes USER instructions
func (s *Scanner) analyzeUserInstruction(parts []string, lineNumber int, result *ScanResult) {
	if len(parts) < 2 {
		return
	}

	user := parts[1]
	if user == "root" || user == "0" {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "root_user",
			Severity:    "high",
			Description: "Container running as root user",
			Line:        lineNumber,
			Instruction: "USER",
		})
	}
}

// checkForSecrets checks for potential secrets in any line
func (s *Scanner) checkForSecrets(line string, lineNumber int, result *ScanResult) {
	secrets := s.rules.FindSecrets(line)
	for _, secret := range secrets {
		secret.Line = lineNumber
		result.Secrets = append(result.Secrets, secret)
	}
}

// parseImageReference parses a Docker image reference into image and tag
func (s *Scanner) parseImageReference(ref string) (string, string) {
	if strings.Contains(ref, ":") {
		parts := strings.Split(ref, ":")
		return parts[0], parts[1]
	}
	return ref, "latest"
}

// checkBaseImageSecurity checks if a base image has known security issues
func (s *Scanner) checkBaseImageSecurity(baseImage *BaseImageInfo) {
	// Check for outdated or vulnerable base images
	if s.rules.IsOutdatedBaseImage(baseImage.Image, baseImage.Tag) {
		baseImage.IsOutdated = true
		baseImage.Severity = "medium"
		baseImage.Reason = "Base image may be outdated or have known vulnerabilities"
	}

	// Check for using latest tag
	if baseImage.Tag == "latest" {
		baseImage.Severity = "low"
		baseImage.Reason = "Using 'latest' tag is not recommended for production"
	}
}

// calculateSummary calculates the scan summary
func (s *Scanner) calculateSummary(result *ScanResult) {
	summary := ScanSummary{}
	
	// Count security issues by severity
	for _, issue := range result.SecurityIssues {
		summary.TotalIssues++
		switch issue.Severity {
		case "high":
			summary.HighSeverity++
		case "medium":
			summary.MediumSeverity++
		case "low":
			summary.LowSeverity++
		default:
			summary.InfoSeverity++
		}
	}

	// Count secrets
	for _, secret := range result.Secrets {
		summary.TotalIssues++
		switch secret.Severity {
		case "high":
			summary.HighSeverity++
		case "medium":
			summary.MediumSeverity++
		case "low":
			summary.LowSeverity++
		default:
			summary.InfoSeverity++
		}
	}

	// Count outdated base images
	for _, baseImage := range result.BaseImages {
		if baseImage.IsOutdated {
			summary.TotalIssues++
			switch baseImage.Severity {
			case "high":
				summary.HighSeverity++
			case "medium":
				summary.MediumSeverity++
			case "low":
				summary.LowSeverity++
			default:
				summary.InfoSeverity++
			}
		}
	}

	result.Summary = summary
}

// PrintJSON prints the scan results in JSON format
func (r *ScanResult) PrintJSON() {
	jsonData, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		color.Red("Error marshaling JSON: %v", err)
		return
	}
	fmt.Println(string(jsonData))
}

// PrintFormatted prints the scan results in a formatted, human-readable way
func (r *ScanResult) PrintFormatted() {
	fmt.Printf("\n")
	color.Cyan("🐳 Docker Scan Lite Results")
	fmt.Printf("\n")
	color.White("Dockerfile: %s", r.Dockerfile)
	color.White("Scanned at: %s", r.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("\n\n")

	// Summary
	color.Yellow("📊 Summary")
	fmt.Printf("Total Issues: %d\n", r.Summary.TotalIssues)
	if r.Summary.HighSeverity > 0 {
		color.Red("  High: %d", r.Summary.HighSeverity)
	}
	if r.Summary.MediumSeverity > 0 {
		color.Yellow("  Medium: %d", r.Summary.MediumSeverity)
	}
	if r.Summary.LowSeverity > 0 {
		color.Blue("  Low: %d", r.Summary.LowSeverity)
	}
	if r.Summary.InfoSeverity > 0 {
		color.White("  Info: %d", r.Summary.InfoSeverity)
	}
	fmt.Printf("\n\n")

	// Base Images
	if len(r.BaseImages) > 0 {
		color.Yellow("🏗️  Base Images")
		for _, img := range r.BaseImages {
			status := "✅"
			if img.IsOutdated {
				status = "⚠️"
			}
			fmt.Printf("  %s %s:%s (line %d)", status, img.Image, img.Tag, img.Line)
			if img.Reason != "" {
				color.White(" - %s", img.Reason)
			}
			fmt.Printf("\n")
		}
		fmt.Printf("\n")
	}

	// Exposed Ports
	if len(r.ExposedPorts) > 0 {
		color.Yellow("🔌 Exposed Ports")
		for _, port := range r.ExposedPorts {
			fmt.Printf("  %s\n", port)
		}
		fmt.Printf("\n")
	}

	// Environment Variables
	if len(r.EnvVars) > 0 {
		color.Yellow("🌍 Environment Variables")
		for _, env := range r.EnvVars {
			status := "✅"
			if env.IsSensitive {
				status = "⚠️"
			}
			fmt.Printf("  %s %s=%s (line %d)\n", status, env.Name, env.Value, env.Line)
		}
		fmt.Printf("\n")
	}

	// Secrets
	if len(r.Secrets) > 0 {
		color.Red("🔐 Potential Secrets")
		for _, secret := range r.Secrets {
			severityColor := color.WhiteString
			switch secret.Severity {
			case "high":
				severityColor = color.RedString
			case "medium":
				severityColor = color.YellowString
			case "low":
				severityColor = color.BlueString
			}
			fmt.Printf("  %s %s: %s (line %d)\n", 
				severityColor("⚠️"), secret.Type, secret.Value, secret.Line)
		}
		fmt.Printf("\n")
	}

	// Security Issues
	if len(r.SecurityIssues) > 0 {
		color.Red("🔒 Security Issues")
		for _, issue := range r.SecurityIssues {
			severityColor := color.WhiteString
			switch issue.Severity {
			case "high":
				severityColor = color.RedString
			case "medium":
				severityColor = color.YellowString
			case "low":
				severityColor = color.BlueString
			}
			fmt.Printf("  %s [%s] %s (line %d)\n", 
				severityColor("⚠️"), strings.ToUpper(issue.Severity), issue.Description, issue.Line)
		}
		fmt.Printf("\n")
	}

	if r.Summary.TotalIssues == 0 {
		color.Green("✅ No security issues found!")
	} else {
		color.Yellow("Review the issues above and consider fixing them to improve security.")
	}
	fmt.Printf("\n")
} 
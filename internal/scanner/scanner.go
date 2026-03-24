package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/nickciolpan/docker-scan-lite/internal/rules"
)

// Scanner represents a Dockerfile scanner
type Scanner struct {
	dockerfilePath string
	verbose        bool
	rules          *rules.Rules
	minSeverity    string
}

// ScanResult holds the results of the scan
type ScanResult struct {
	Dockerfile     string             `json:"dockerfile"`
	Timestamp      time.Time          `json:"timestamp"`
	BaseImages     []BaseImageInfo    `json:"base_images"`
	ExposedPorts   []string           `json:"exposed_ports"`
	EnvVars        []EnvVarInfo       `json:"env_vars"`
	Secrets        []rules.SecretInfo `json:"secrets"`
	SecurityIssues []SecurityIssue    `json:"security_issues"`
	Stages         []StageInfo        `json:"stages"`
	Summary        ScanSummary        `json:"summary"`
}

// StageInfo tracks multi-stage build information
type StageInfo struct {
	Name    string `json:"name"`
	Image   string `json:"image"`
	Line    int    `json:"line"`
	IsFinal bool   `json:"is_final"`
}

// BaseImageInfo contains information about base images
type BaseImageInfo struct {
	Image      string `json:"image"`
	Tag        string `json:"tag"`
	Line       int    `json:"line"`
	IsOutdated bool   `json:"is_outdated"`
	Severity   string `json:"severity"`
	Reason     string `json:"reason"`
	Stage      string `json:"stage,omitempty"`
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
	Stage       string `json:"stage,omitempty"`
}

// ScanSummary provides a summary of the scan results
type ScanSummary struct {
	TotalIssues    int `json:"total_issues"`
	HighSeverity   int `json:"high_severity"`
	MediumSeverity int `json:"medium_severity"`
	LowSeverity    int `json:"low_severity"`
	InfoSeverity   int `json:"info_severity"`
}

// severityRank returns a numeric rank for severity comparison
func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info":
		return 0
	default:
		return -1
	}
}

// NewScanner creates a new scanner instance
func NewScanner(dockerfilePath string, verbose bool) *Scanner {
	return &Scanner{
		dockerfilePath: dockerfilePath,
		verbose:        verbose,
		rules:          rules.New(),
		minSeverity:    "",
	}
}

// SetMinSeverity sets the minimum severity to report
func (s *Scanner) SetMinSeverity(severity string) {
	s.minSeverity = strings.ToLower(severity)
}

// shouldReport checks if an issue meets the minimum severity threshold
func (s *Scanner) shouldReport(severity string) bool {
	if s.minSeverity == "" {
		return true
	}
	return severityRank(severity) >= severityRank(s.minSeverity)
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
		Stages:         []StageInfo{},
	}

	sc := bufio.NewScanner(file)
	lineNumber := 0
	var continuedLine string
	var continuedLineNumber int

	currentStage := ""
	hasHealthcheck := false
	hasUserInstruction := false
	stageCount := 0

	for sc.Scan() {
		lineNumber++
		line := strings.TrimSpace(sc.Text())

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
				line = continuedLine + line
				lineNumber = continuedLineNumber
				continuedLine = ""
				continuedLineNumber = 0
			}
		}

		instruction := strings.ToUpper(strings.Fields(line)[0])

		// Track multi-stage builds
		if instruction == "FROM" {
			stageCount++
			// Mark previous stages as non-final
			for i := range result.Stages {
				result.Stages[i].IsFinal = false
			}
			parts := strings.Fields(line)
			stageName := ""
			for i, p := range parts {
				if strings.EqualFold(p, "as") && i+1 < len(parts) {
					stageName = parts[i+1]
					break
				}
			}
			if stageName == "" {
				stageName = fmt.Sprintf("stage-%d", stageCount)
			}
			currentStage = stageName
			result.Stages = append(result.Stages, StageInfo{
				Name:    stageName,
				Image:   parts[1],
				Line:    lineNumber,
				IsFinal: true,
			})
			// Reset per-stage tracking
			hasUserInstruction = false
		}

		if instruction == "HEALTHCHECK" {
			hasHealthcheck = true
		}

		if instruction == "USER" {
			hasUserInstruction = true
		}

		s.analyzeLine(line, lineNumber, result, currentStage)
	}

	// Handle case where file ends with a continued line
	if continuedLine != "" {
		s.analyzeLine(continuedLine, continuedLineNumber, result, currentStage)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("error reading Dockerfile: %v", err)
	}

	// Post-scan checks
	if stageCount > 0 && !hasHealthcheck {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "missing_healthcheck",
			Severity:    "info",
			Description: "No HEALTHCHECK instruction found. Consider adding one for container orchestration",
			Line:        0,
			Instruction: "HEALTHCHECK",
		})
	}

	if stageCount > 0 && !hasUserInstruction {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "missing_user",
			Severity:    "medium",
			Description: "No USER instruction found in final stage. Container will run as root by default",
			Line:        0,
			Instruction: "USER",
		})
	}

	s.calculateSummary(result)
	return result, nil
}

// analyzeLine analyzes a single line of the Dockerfile
func (s *Scanner) analyzeLine(line string, lineNumber int, result *ScanResult, stage string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	instruction := strings.ToUpper(parts[0])

	switch instruction {
	case "FROM":
		s.analyzeFromInstruction(parts, lineNumber, result, stage)
	case "EXPOSE":
		s.analyzeExposeInstruction(parts, lineNumber, result, stage)
	case "ENV":
		s.analyzeEnvInstruction(line, lineNumber, result, stage)
	case "RUN":
		s.analyzeRunInstruction(line, lineNumber, result, stage)
	case "ADD", "COPY":
		s.analyzeFileInstruction(line, lineNumber, result, stage)
	case "USER":
		s.analyzeUserInstruction(parts, lineNumber, result, stage)
	case "SHELL":
		s.analyzeShellInstruction(line, lineNumber, result, stage)
	}

	// Check for secrets in any instruction
	s.checkForSecrets(line, lineNumber, result)
}

// analyzeFromInstruction analyzes FROM instructions for base image info
func (s *Scanner) analyzeFromInstruction(parts []string, lineNumber int, result *ScanResult, stage string) {
	if len(parts) < 2 {
		return
	}

	imageRef := parts[1]

	image, tag := parseImageReference(imageRef)

	baseImage := BaseImageInfo{
		Image: image,
		Tag:   tag,
		Line:  lineNumber,
		Stage: stage,
	}

	s.checkBaseImageSecurity(&baseImage)

	result.BaseImages = append(result.BaseImages, baseImage)
}

// analyzeExposeInstruction analyzes EXPOSE instructions
func (s *Scanner) analyzeExposeInstruction(parts []string, lineNumber int, result *ScanResult, stage string) {
	for i := 1; i < len(parts); i++ {
		port := parts[i]
		result.ExposedPorts = append(result.ExposedPorts, port)

		if s.rules.IsVulnerablePort(port) {
			result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
				Type:        "vulnerable_port",
				Severity:    "medium",
				Description: fmt.Sprintf("Port %s may be vulnerable or should not be exposed", port),
				Line:        lineNumber,
				Instruction: "EXPOSE",
				Stage:       stage,
			})
		}
	}
}

// analyzeEnvInstruction analyzes ENV instructions
func (s *Scanner) analyzeEnvInstruction(line string, lineNumber int, result *ScanResult, stage string) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	// Handle ENV KEY=value KEY2=value2 format
	if strings.Contains(parts[1], "=") {
		for i := 1; i < len(parts); i++ {
			part := parts[i]
			if !strings.Contains(part, "=") {
				continue
			}
			kv := strings.SplitN(part, "=", 2)
			name := kv[0]
			value := ""
			if len(kv) > 1 {
				value = kv[1]
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
					Stage:       stage,
				})
			}
		}
	} else {
		// ENV KEY value format
		name := parts[1]
		value := ""
		if len(parts) > 2 {
			value = strings.Join(parts[2:], " ")
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
				Stage:       stage,
			})
		}
	}
}

// analyzeRunInstruction analyzes RUN instructions
func (s *Scanner) analyzeRunInstruction(line string, lineNumber int, result *ScanResult, stage string) {
	if s.rules.HasInsecureCommand(line) {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "insecure_command",
			Severity:    "medium",
			Description: "Potentially insecure command detected",
			Line:        lineNumber,
			Instruction: "RUN",
			Stage:       stage,
		})
	}

	if s.rules.HasUnpinnedPackages(line) {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "unpinned_packages",
			Severity:    "low",
			Description: "Package installation without version pinning detected",
			Line:        lineNumber,
			Instruction: "RUN",
			Stage:       stage,
		})
	}
}

// analyzeFileInstruction analyzes ADD/COPY instructions
func (s *Scanner) analyzeFileInstruction(line string, lineNumber int, result *ScanResult, stage string) {
	if strings.HasPrefix(strings.ToUpper(line), "ADD") && strings.Contains(line, "http") {
		result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
			Type:        "remote_file_add",
			Severity:    "medium",
			Description: "ADD instruction with remote URL detected, consider using COPY instead",
			Line:        lineNumber,
			Instruction: "ADD",
			Stage:       stage,
		})
	}
}

// analyzeUserInstruction analyzes USER instructions
func (s *Scanner) analyzeUserInstruction(parts []string, lineNumber int, result *ScanResult, stage string) {
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
			Stage:       stage,
		})
	}
}

// analyzeShellInstruction analyzes SHELL instructions
func (s *Scanner) analyzeShellInstruction(line string, lineNumber int, result *ScanResult, stage string) {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "/bin/sh") || strings.Contains(lower, "cmd") {
		return // default shells, fine
	}
	if strings.Contains(lower, "powershell") {
		return // acceptable
	}
	// Warn about non-standard shells
	result.SecurityIssues = append(result.SecurityIssues, SecurityIssue{
		Type:        "custom_shell",
		Severity:    "info",
		Description: "Non-standard SHELL instruction detected. Verify it is intentional",
		Line:        lineNumber,
		Instruction: "SHELL",
		Stage:       stage,
	})
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
func parseImageReference(ref string) (string, string) {
	// Handle digest references (image@sha256:...)
	if strings.Contains(ref, "@") {
		parts := strings.SplitN(ref, "@", 2)
		return parts[0], parts[1]
	}
	if strings.Contains(ref, ":") {
		parts := strings.SplitN(ref, ":", 2)
		return parts[0], parts[1]
	}
	return ref, "latest"
}

// checkBaseImageSecurity checks if a base image has known security issues
func (s *Scanner) checkBaseImageSecurity(baseImage *BaseImageInfo) {
	// scratch is a special Docker keyword, not a real image
	if baseImage.Image == "scratch" {
		return
	}

	if s.rules.IsOutdatedBaseImage(baseImage.Image, baseImage.Tag) {
		baseImage.IsOutdated = true
		baseImage.Severity = "medium"
		baseImage.Reason = "Base image may be outdated or have known vulnerabilities"
	}

	if baseImage.Tag == "latest" {
		baseImage.Severity = "low"
		baseImage.Reason = "Using 'latest' tag is not recommended for production"
	}
}

// calculateSummary calculates the scan summary
func (s *Scanner) calculateSummary(result *ScanResult) {
	summary := ScanSummary{}

	for _, issue := range result.SecurityIssues {
		if !s.shouldReport(issue.Severity) {
			continue
		}
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

	for _, secret := range result.Secrets {
		if !s.shouldReport(secret.Severity) {
			continue
		}
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

	for _, baseImage := range result.BaseImages {
		if baseImage.IsOutdated {
			if !s.shouldReport(baseImage.Severity) {
				continue
			}
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

// ExitCode returns 0 if no issues at or above the threshold, 1 otherwise
func (r *ScanResult) ExitCode(failOn string) int {
	if failOn == "" {
		failOn = "high"
	}
	threshold := severityRank(failOn)

	for _, issue := range r.SecurityIssues {
		if severityRank(issue.Severity) >= threshold {
			return 1
		}
	}
	for _, secret := range r.Secrets {
		if severityRank(secret.Severity) >= threshold {
			return 1
		}
	}
	for _, img := range r.BaseImages {
		if img.IsOutdated && severityRank(img.Severity) >= threshold {
			return 1
		}
	}
	return 0
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

// PrintSARIF prints the scan results in SARIF format
func (r *ScanResult) PrintSARIF() {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "docker-scan-lite",
						"informationUri": "https://github.com/nickciolpan/docker-scan-lite",
						"rules":          r.sarifRules(),
					},
				},
				"results": r.sarifResults(),
			},
		},
	}
	jsonData, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		color.Red("Error marshaling SARIF: %v", err)
		return
	}
	fmt.Println(string(jsonData))
}

func (r *ScanResult) sarifRules() []map[string]interface{} {
	ruleMap := map[string]bool{}
	var out []map[string]interface{}
	for _, issue := range r.SecurityIssues {
		if ruleMap[issue.Type] {
			continue
		}
		ruleMap[issue.Type] = true
		out = append(out, map[string]interface{}{
			"id": issue.Type,
			"shortDescription": map[string]string{
				"text": issue.Description,
			},
			"defaultConfiguration": map[string]string{
				"level": sarifLevel(issue.Severity),
			},
		})
	}
	for _, secret := range r.Secrets {
		if ruleMap[secret.Type] {
			continue
		}
		ruleMap[secret.Type] = true
		out = append(out, map[string]interface{}{
			"id": secret.Type,
			"shortDescription": map[string]string{
				"text": "Potential secret detected: " + secret.Type,
			},
			"defaultConfiguration": map[string]string{
				"level": sarifLevel(secret.Severity),
			},
		})
	}
	return out
}

func (r *ScanResult) sarifResults() []map[string]interface{} {
	var out []map[string]interface{}
	for _, issue := range r.SecurityIssues {
		out = append(out, map[string]interface{}{
			"ruleId":  issue.Type,
			"level":   sarifLevel(issue.Severity),
			"message": map[string]string{"text": issue.Description},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": r.Dockerfile,
						},
						"region": map[string]int{
							"startLine": issue.Line,
						},
					},
				},
			},
		})
	}
	for _, secret := range r.Secrets {
		out = append(out, map[string]interface{}{
			"ruleId":  secret.Type,
			"level":   sarifLevel(secret.Severity),
			"message": map[string]string{"text": fmt.Sprintf("Potential %s detected", secret.Type)},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": r.Dockerfile,
						},
						"region": map[string]int{
							"startLine": secret.Line,
						},
					},
				},
			},
		})
	}
	return out
}

func sarifLevel(severity string) string {
	switch severity {
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "note"
	}
}

// PrintFormatted prints the scan results in a formatted, human-readable way
func (r *ScanResult) PrintFormatted() {
	fmt.Printf("\n")
	color.Cyan("Docker Scan Lite Results")
	fmt.Printf("\n")
	color.White("Dockerfile: %s", r.Dockerfile)
	color.White("Scanned at: %s", r.Timestamp.Format("2006-01-02 15:04:05"))
	if len(r.Stages) > 1 {
		color.White("Build stages: %d", len(r.Stages))
	}
	fmt.Printf("\n\n")

	// Summary
	color.Yellow("Summary")
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
		color.Yellow("Base Images")
		for _, img := range r.BaseImages {
			status := "✅"
			if img.IsOutdated {
				status = "⚠️"
			}
			if img.Image == "scratch" {
				fmt.Printf("  ✅ scratch (line %d)\n", img.Line)
				continue
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
		color.Yellow("Exposed Ports")
		for _, port := range r.ExposedPorts {
			fmt.Printf("  %s\n", port)
		}
		fmt.Printf("\n")
	}

	// Environment Variables
	if len(r.EnvVars) > 0 {
		color.Yellow("Environment Variables")
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
		color.Red("Potential Secrets")
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
		color.Red("Security Issues")
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
			lineStr := ""
			if issue.Line > 0 {
				lineStr = fmt.Sprintf(" (line %d)", issue.Line)
			}
			fmt.Printf("  %s [%s] %s%s\n",
				severityColor("⚠️"), strings.ToUpper(issue.Severity), issue.Description, lineStr)
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

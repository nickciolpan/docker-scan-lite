package rules

import (
	"regexp"
	"strings"
)

// SecretInfo contains information about potential secrets
type SecretInfo struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	Line       int    `json:"line"`
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
}

// Rules contains all security rules and patterns
type Rules struct {
	secretPatterns      map[string]*regexp.Regexp
	vulnerablePorts     map[string]bool
	sensitiveEnvVars    map[string]bool
	outdatedImages      map[string]bool
	insecureCommands    []*regexp.Regexp
	unpinnedPackages    []*regexp.Regexp
}

// New creates a new Rules instance with predefined security rules
func New() *Rules {
	r := &Rules{
		secretPatterns:   make(map[string]*regexp.Regexp),
		vulnerablePorts:  make(map[string]bool),
		sensitiveEnvVars: make(map[string]bool),
		outdatedImages:   make(map[string]bool),
	}

	r.initializeSecretPatterns()
	r.initializeVulnerablePorts()
	r.initializeSensitiveEnvVars()
	r.initializeOutdatedImages()
	r.initializeInsecureCommands()
	r.initializeUnpinnedPackagePatterns()

	return r
}

// initializeSecretPatterns sets up regex patterns for detecting secrets
func (r *Rules) initializeSecretPatterns() {
	patterns := map[string]string{
		"aws_access_key":    `AKIA[0-9A-Z]{16}`,
		"aws_secret_key":    `[0-9a-zA-Z/+]{40}`,
		"github_token":      `ghp_[0-9a-zA-Z]{36}`,
		"slack_token":       `xox[baprs]-[0-9a-zA-Z\-]+`,
		"generic_api_key":   `[aA][pP][iI]_?[kK][eE][yY].*[=:]\s*['\"]?[0-9a-zA-Z\-_]{20,}['\"]?`,
		"generic_password":  `[pP][aA][sS][sS][wW][oO][rR][dD].*[=:]\s*['\"]?[^\s'\"]{6,}['\"]?`,
		"generic_secret":    `[sS][eE][cC][rR][eE][tT].*[=:]\s*['\"]?[0-9a-zA-Z\-_]{10,}['\"]?`,
		"generic_token":     `[tT][oO][kK][eE][nN].*[=:]\s*['\"]?[0-9a-zA-Z\-_]{20,}['\"]?`,
		"private_key":       `-----BEGIN [A-Z ]+PRIVATE KEY-----`,
		"jwt_token":         `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`,
		"database_url":      `(postgres|postgresql|mysql|mongodb|mongodb\+srv|redis|amqp|mssql|sqlite|couchdb|memcached)://[^\s'"]+`,
	}

	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err == nil {
			r.secretPatterns[name] = compiled
		}
	}
}

// initializeVulnerablePorts sets up commonly vulnerable ports
func (r *Rules) initializeVulnerablePorts() {
	vulnerablePorts := []string{
		"22",    // SSH
		"23",    // Telnet
		"25",    // SMTP
		"53",    // DNS
		"110",   // POP3
		"143",   // IMAP
		"993",   // IMAPS
		"995",   // POP3S
		"1433",  // SQL Server
		"1521",  // Oracle
		"2049",  // NFS
		"3306",  // MySQL
		"3389",  // RDP
		"5432",  // PostgreSQL
		"5984",  // CouchDB
		"6379",  // Redis
		"8086",  // InfluxDB
		"9200",  // Elasticsearch
		"27017", // MongoDB
		"27018", // MongoDB
		"27019", // MongoDB
	}

	for _, port := range vulnerablePorts {
		r.vulnerablePorts[port] = true
	}
}

// initializeSensitiveEnvVars sets up sensitive environment variable names
func (r *Rules) initializeSensitiveEnvVars() {
	sensitiveVars := []string{
		"PASSWORD", "PASSWD", "PWD",
		"SECRET", "SECRET_KEY", "SECRET_TOKEN",
		"API_KEY", "APIKEY", "API_SECRET",
		"TOKEN", "ACCESS_TOKEN", "AUTH_TOKEN",
		"PRIVATE_KEY", "PRIV_KEY",
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"DATABASE_URL", "DB_PASSWORD", "DB_PASS",
		"MYSQL_PASSWORD", "POSTGRES_PASSWORD",
		"REDIS_PASSWORD", "MONGODB_PASSWORD",
		"JWT_SECRET", "SESSION_SECRET",
		"GITHUB_TOKEN", "SLACK_TOKEN",
		"SMTP_PASSWORD", "EMAIL_PASSWORD",
	}

	for _, varName := range sensitiveVars {
		r.sensitiveEnvVars[strings.ToUpper(varName)] = true
	}
}

// initializeOutdatedImages sets up known outdated or vulnerable base images
func (r *Rules) initializeOutdatedImages() {
	outdatedImages := []string{
		"ubuntu:12.04", "ubuntu:14.04", "ubuntu:16.04",
		"debian:7", "debian:8", "debian:9",
		"centos:6", "centos:7",
		"alpine:3.3", "alpine:3.4", "alpine:3.5", "alpine:3.6", "alpine:3.7", "alpine:3.8", "alpine:3.9", "alpine:3.10",
		"node:8", "node:10", "node:12",
		"python:2.7", "python:3.5", "python:3.6",
		"ruby:2.4", "ruby:2.5",
		"openjdk:8", "openjdk:11",
		"nginx:1.12", "nginx:1.13", "nginx:1.14", "nginx:1.15",
		"redis:3", "redis:4",
		"mysql:5.6", "mysql:5.7",
		"postgres:9", "postgres:10", "postgres:11",
	}

	for _, image := range outdatedImages {
		r.outdatedImages[image] = true
	}
}

// initializeInsecureCommands sets up patterns for insecure commands
func (r *Rules) initializeInsecureCommands() {
	patterns := []string{
		`curl.*-k`,                    // curl with -k (insecure)
		`wget.*--no-check-certificate`, // wget without certificate check
		`chmod\s+777`,                 // overly permissive permissions
		`su\s+root`,                   // switching to root
		`sudo\s+su`,                   // sudo su
		`ssh.*-o.*StrictHostKeyChecking=no`, // SSH without host key checking
		`--allow-unauthenticated`,     // apt-get with unauthenticated packages
	}

	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err == nil {
			r.insecureCommands = append(r.insecureCommands, compiled)
		}
	}
}

// initializeUnpinnedPackagePatterns sets up patterns for unpinned package installations
func (r *Rules) initializeUnpinnedPackagePatterns() {
	patterns := []string{
		`apt-get\s+install\s+[^&]+[^=\s]+\s*$`,    // apt-get install without version (excluding lines ending with \)
		`yum\s+install\s+[^&]+[^=\s]+\s*$`,        // yum install without version  
		`pip\s+install\s+[^&]+[^=\s]+\s*$`,        // pip install without version
		`npm\s+install\s+[^&]+[^@\s]+\s*$`,        // npm install without version
		`gem\s+install\s+[^&]+[^=\s]+\s*$`,        // gem install without version
		`apk\s+add\s+[^&]+[^=\s]+\s*$`,            // apk add without version
	}

	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err == nil {
			r.unpinnedPackages = append(r.unpinnedPackages, compiled)
		}
	}
}

// IsVulnerablePort checks if a port is commonly vulnerable
func (r *Rules) IsVulnerablePort(port string) bool {
	// Remove protocol suffix if present (e.g., "80/tcp" -> "80")
	if idx := strings.Index(port, "/"); idx != -1 {
		port = port[:idx]
	}
	return r.vulnerablePorts[port]
}

// IsSensitiveEnvVar checks if an environment variable name is sensitive
func (r *Rules) IsSensitiveEnvVar(name string) bool {
	upperName := strings.ToUpper(name)
	
	// Direct match
	if r.sensitiveEnvVars[upperName] {
		return true
	}

	// Pattern matching for common sensitive patterns
	sensitivePatterns := []string{"PASSWORD", "SECRET", "KEY", "TOKEN", "PASS"}
	for _, pattern := range sensitivePatterns {
		if strings.Contains(upperName, pattern) {
			return true
		}
	}

	return false
}

// IsOutdatedBaseImage checks if a base image is known to be outdated
func (r *Rules) IsOutdatedBaseImage(image, tag string) bool {
	fullImage := image + ":" + tag
	return r.outdatedImages[fullImage]
}

// HasInsecureCommand checks if a command contains insecure patterns
func (r *Rules) HasInsecureCommand(command string) bool {
	for _, pattern := range r.insecureCommands {
		if pattern.MatchString(command) {
			return true
		}
	}
	return false
}

// HasUnpinnedPackages checks if a command installs packages without version pinning
func (r *Rules) HasUnpinnedPackages(command string) bool {
	// Check for common package managers
	if strings.Contains(command, "apt-get install") {
		// Look for packages without = (version specification) 
		if !strings.Contains(command, "=") && !strings.Contains(command, "--no-install-recommends") {
			// Skip if it's just flags or ends with continuation
			words := strings.Fields(command)
			for _, word := range words {
				if !strings.HasPrefix(word, "-") && word != "apt-get" && word != "install" && word != "&&" && word != "\\" {
					return true
				}
			}
		}
	}
	
	if strings.Contains(command, "apk add") {
		// Look for packages without = (version specification)
		if !strings.Contains(command, "=") {
			// Skip if it's just flags or ends with continuation
			words := strings.Fields(command)
			hasPackage := false
			for _, word := range words {
				if !strings.HasPrefix(word, "-") && word != "apk" && word != "add" && word != "&&" && word != "\\" {
					hasPackage = true
					break
				}
			}
			return hasPackage
		}
	}
	
	if strings.Contains(command, "yum install") && !strings.Contains(command, "=") {
		words := strings.Fields(command)
		for _, word := range words {
			if !strings.HasPrefix(word, "-") && word != "yum" && word != "install" && word != "&&" && word != "\\" {
				return true
			}
		}
	}
	
	if strings.Contains(command, "pip install") && !strings.Contains(command, "==") {
		words := strings.Fields(command)
		for _, word := range words {
			if !strings.HasPrefix(word, "-") && word != "pip" && word != "install" && word != "&&" && word != "\\" {
				return true
			}
		}
	}
	
	if strings.Contains(command, "npm install") && !strings.Contains(command, "@") {
		words := strings.Fields(command)
		for _, word := range words {
			if !strings.HasPrefix(word, "-") && word != "npm" && word != "install" && word != "&&" && word != "\\" {
				return true
			}
		}
	}
	
	return false
}

// FindSecrets finds potential secrets in a line of text
func (r *Rules) FindSecrets(line string) []SecretInfo {
	var secrets []SecretInfo

	for secretType, pattern := range r.secretPatterns {
		matches := pattern.FindAllString(line, -1)
		for _, match := range matches {
			severity := "medium"
			confidence := "medium"

			// Adjust severity and confidence based on secret type
			switch secretType {
			case "private_key", "aws_access_key", "aws_secret_key":
				severity = "high"
				confidence = "high"
			case "jwt_token", "github_token":
				severity = "high"
				confidence = "high"
			case "generic_password", "generic_secret":
				severity = "medium"
				confidence = "low"
			}

			secrets = append(secrets, SecretInfo{
				Type:       secretType,
				Value:      match,
				Severity:   severity,
				Confidence: confidence,
			})
		}
	}

	return secrets
} 
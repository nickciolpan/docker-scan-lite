package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempDockerfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp Dockerfile: %v", err)
	}
	return path
}

func TestScanEmpty(t *testing.T) {
	path := writeTempDockerfile(t, "")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.BaseImages) != 0 {
		t.Errorf("expected 0 base images, got %d", len(result.BaseImages))
	}
	if result.Summary.TotalIssues != 0 {
		t.Errorf("expected 0 issues for empty file, got %d", result.Summary.TotalIssues)
	}
}

func TestScanScratch(t *testing.T) {
	path := writeTempDockerfile(t, "FROM scratch\nCOPY app /app\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.BaseImages) != 1 {
		t.Fatalf("expected 1 base image, got %d", len(result.BaseImages))
	}
	img := result.BaseImages[0]
	if img.Image != "scratch" {
		t.Errorf("expected image 'scratch', got %q", img.Image)
	}
	if img.IsOutdated {
		t.Error("scratch should not be flagged as outdated")
	}
	if img.Reason != "" {
		t.Errorf("scratch should have no reason, got %q", img.Reason)
	}
}

func TestScanOutdatedImage(t *testing.T) {
	path := writeTempDockerfile(t, "FROM ubuntu:16.04\nRUN echo hi\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.BaseImages) != 1 {
		t.Fatalf("expected 1 base image, got %d", len(result.BaseImages))
	}
	if !result.BaseImages[0].IsOutdated {
		t.Error("ubuntu:16.04 should be flagged as outdated")
	}
}

func TestScanLatestTag(t *testing.T) {
	path := writeTempDockerfile(t, "FROM nginx\nEXPOSE 80\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	img := result.BaseImages[0]
	if img.Tag != "latest" {
		t.Errorf("expected tag 'latest', got %q", img.Tag)
	}
	if img.Reason == "" {
		t.Error("should warn about latest tag")
	}
}

func TestScanENVKeyValueFormat(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nENV DATABASE_PASSWORD=secret123\nENV API_KEY=abc123456789\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.EnvVars) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(result.EnvVars))
	}
	if result.EnvVars[0].Name != "DATABASE_PASSWORD" {
		t.Errorf("expected DATABASE_PASSWORD, got %q", result.EnvVars[0].Name)
	}
	if result.EnvVars[0].Value != "secret123" {
		t.Errorf("expected 'secret123', got %q", result.EnvVars[0].Value)
	}
	if !result.EnvVars[0].IsSensitive {
		t.Error("DATABASE_PASSWORD should be flagged as sensitive")
	}
}

func TestScanENVMultipleKeyValue(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nENV FOO=bar BAZ=qux\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.EnvVars) != 2 {
		t.Fatalf("expected 2 env vars, got %d", len(result.EnvVars))
	}
	if result.EnvVars[0].Name != "FOO" || result.EnvVars[1].Name != "BAZ" {
		t.Errorf("unexpected env var names: %q, %q", result.EnvVars[0].Name, result.EnvVars[1].Name)
	}
}

func TestScanENVSpaceFormat(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nENV MY_VAR hello world\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.EnvVars) != 1 {
		t.Fatalf("expected 1 env var, got %d", len(result.EnvVars))
	}
	if result.EnvVars[0].Value != "hello world" {
		t.Errorf("expected 'hello world', got %q", result.EnvVars[0].Value)
	}
}

func TestScanVulnerablePorts(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nEXPOSE 22 3306 8080\nUSER appuser\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.ExposedPorts) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(result.ExposedPorts))
	}
	vulnCount := 0
	for _, issue := range result.SecurityIssues {
		if issue.Type == "vulnerable_port" {
			vulnCount++
		}
	}
	if vulnCount != 2 {
		t.Errorf("expected 2 vulnerable port issues (22, 3306), got %d", vulnCount)
	}
}

func TestScanRootUser(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nUSER root\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "root_user" {
			found = true
			if issue.Severity != "high" {
				t.Errorf("root_user should be high severity, got %q", issue.Severity)
			}
		}
	}
	if !found {
		t.Error("expected root_user issue")
	}
}

func TestScanInsecureCommands(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nRUN curl -k https://example.com\nRUN chmod 777 /app\nUSER app\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	count := 0
	for _, issue := range result.SecurityIssues {
		if issue.Type == "insecure_command" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 insecure_command issues, got %d", count)
	}
}

func TestScanADDRemoteURL(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nADD https://example.com/file.tar.gz /app/\nUSER app\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "remote_file_add" {
			found = true
		}
	}
	if !found {
		t.Error("expected remote_file_add issue")
	}
}

func TestScanMissingHealthcheck(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nRUN echo hi\nUSER app\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "missing_healthcheck" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_healthcheck issue")
	}
}

func TestScanWithHealthcheck(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nUSER app\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	for _, issue := range result.SecurityIssues {
		if issue.Type == "missing_healthcheck" {
			t.Error("should not flag missing_healthcheck when HEALTHCHECK is present")
		}
	}
}

func TestScanMissingUser(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nRUN echo hi\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "missing_user" {
			found = true
		}
	}
	if !found {
		t.Error("expected missing_user issue")
	}
}

func TestScanWithUser(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nUSER appuser\n")
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	for _, issue := range result.SecurityIssues {
		if issue.Type == "missing_user" {
			t.Error("should not flag missing_user when USER is present")
		}
	}
}

func TestScanMultiStage(t *testing.T) {
	dockerfile := `FROM golang:1.21 AS builder
RUN go build -o /app
FROM alpine:3.18
COPY --from=builder /app /app
USER appuser
`
	path := writeTempDockerfile(t, dockerfile)
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(result.Stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(result.Stages))
	}
	if result.Stages[0].IsFinal {
		t.Error("first stage should not be final")
	}
	if !result.Stages[1].IsFinal {
		t.Error("second stage should be final")
	}
	if result.Stages[0].Name != "builder" {
		t.Errorf("expected stage name 'builder', got %q", result.Stages[0].Name)
	}
}

func TestScanLineContinuation(t *testing.T) {
	dockerfile := `FROM alpine:3.18
RUN apk add --no-cache \
    curl \
    wget
USER app
`
	path := writeTempDockerfile(t, dockerfile)
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	// Should detect unpinned packages in continued line
	found := false
	for _, issue := range result.SecurityIssues {
		if issue.Type == "unpinned_packages" {
			found = true
		}
	}
	if !found {
		t.Error("expected unpinned_packages issue for continued line")
	}
}

func TestScanSecretDetection(t *testing.T) {
	dockerfile := `FROM alpine:3.18
RUN echo "-----BEGIN RSA PRIVATE KEY-----"
ENV DB=postgresql://user:pass@host/db
USER app
`
	path := writeTempDockerfile(t, dockerfile)
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	types := map[string]bool{}
	for _, s := range result.Secrets {
		types[s.Type] = true
	}
	if !types["private_key"] {
		t.Error("expected private_key secret")
	}
	if !types["database_url"] {
		t.Error("expected database_url secret")
	}
}

func TestScanNoFalsePositiveURLs(t *testing.T) {
	dockerfile := `FROM alpine:3.18
RUN curl -fsSL https://example.com/install.sh | sh
ADD https://github.com/user/repo/archive/main.tar.gz /app/
USER app
`
	path := writeTempDockerfile(t, dockerfile)
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	for _, s := range result.Secrets {
		if s.Type == "database_url" {
			t.Errorf("false positive database_url: %q", s.Value)
		}
	}
}

func TestExitCode(t *testing.T) {
	// High severity issues
	path := writeTempDockerfile(t, "FROM alpine:3.18\nUSER root\n")
	s := NewScanner(path, false)
	result, _ := s.Scan()

	if result.ExitCode("high") != 1 {
		t.Error("expected exit code 1 for high severity with root user")
	}
	if result.ExitCode("") != 1 {
		t.Error("expected exit code 1 with default (high) threshold")
	}

	// Clean file
	path = writeTempDockerfile(t, "FROM alpine:3.18\nUSER app\nHEALTHCHECK CMD true\n")
	s = NewScanner(path, false)
	result, _ = s.Scan()

	if result.ExitCode("high") != 0 {
		t.Error("expected exit code 0 for clean file with high threshold")
	}
}

func TestExitCodeMedium(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nEXPOSE 22\nUSER app\nHEALTHCHECK CMD true\n")
	s := NewScanner(path, false)
	result, _ := s.Scan()

	if result.ExitCode("medium") != 1 {
		t.Error("expected exit code 1 for medium threshold with vulnerable port")
	}
	if result.ExitCode("high") != 0 {
		t.Error("expected exit code 0 for high threshold with only medium issues")
	}
}

func TestMinSeverityFilter(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nEXPOSE 22\nRUN apt-get install curl\nUSER root\n")
	s := NewScanner(path, false)
	s.SetMinSeverity("high")
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	// With high severity filter, only high issues should be counted in summary
	if result.Summary.MediumSeverity != 0 {
		t.Errorf("expected 0 medium in summary with high filter, got %d", result.Summary.MediumSeverity)
	}
	if result.Summary.LowSeverity != 0 {
		t.Errorf("expected 0 low in summary with high filter, got %d", result.Summary.LowSeverity)
	}
	if result.Summary.HighSeverity == 0 {
		t.Error("expected some high severity issues in summary")
	}
}

func TestScanFileNotFound(t *testing.T) {
	s := NewScanner("/nonexistent/Dockerfile", false)
	_, err := s.Scan()
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseImageReference(t *testing.T) {
	tests := []struct {
		ref       string
		wantImage string
		wantTag   string
	}{
		{"ubuntu:22.04", "ubuntu", "22.04"},
		{"nginx", "nginx", "latest"},
		{"myregistry.com/myimage:v1.0", "myregistry.com/myimage", "v1.0"},
		{"python:3.11-slim", "python", "3.11-slim"},
		{"alpine@sha256:abc123", "alpine", "sha256:abc123"},
		{"scratch", "scratch", "latest"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			image, tag := parseImageReference(tt.ref)
			if image != tt.wantImage {
				t.Errorf("parseImageReference(%q) image = %q, want %q", tt.ref, image, tt.wantImage)
			}
			if tag != tt.wantTag {
				t.Errorf("parseImageReference(%q) tag = %q, want %q", tt.ref, tag, tt.wantTag)
			}
		})
	}
}

func TestScanCleanDockerfile(t *testing.T) {
	dockerfile := `FROM alpine:3.18
RUN addgroup -g 1000 app && adduser -D -u 1000 -G app app
RUN apk add --no-cache curl=8.2.1-r0
USER app
EXPOSE 8080
HEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1
CMD ["echo", "hello"]
`
	path := writeTempDockerfile(t, dockerfile)
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result.Summary.HighSeverity != 0 {
		t.Errorf("expected 0 high severity, got %d", result.Summary.HighSeverity)
	}
	if result.Summary.MediumSeverity != 0 {
		t.Errorf("expected 0 medium severity, got %d", result.Summary.MediumSeverity)
	}
}

func TestPrintJSON(t *testing.T) {
	path := writeTempDockerfile(t, "FROM alpine:3.18\nUSER app\nHEALTHCHECK CMD true\n")
	s := NewScanner(path, false)
	result, _ := s.Scan()
	// Just verify it doesn't panic
	result.PrintJSON()
}

func TestPrintSARIF(t *testing.T) {
	path := writeTempDockerfile(t, "FROM ubuntu:16.04\nUSER root\n")
	s := NewScanner(path, false)
	result, _ := s.Scan()
	// Just verify it doesn't panic
	result.PrintSARIF()
}

func TestPrintFormatted(t *testing.T) {
	path := writeTempDockerfile(t, "FROM ubuntu:16.04\nENV PASSWORD=test\nEXPOSE 22\nUSER root\n")
	s := NewScanner(path, false)
	result, _ := s.Scan()
	// Just verify it doesn't panic
	result.PrintFormatted()
}

func TestScanSummaryCountsCorrectly(t *testing.T) {
	dockerfile := `FROM ubuntu:16.04
ENV DATABASE_PASSWORD=secret
EXPOSE 22
RUN curl -k https://example.com
USER root
`
	path := writeTempDockerfile(t, dockerfile)
	s := NewScanner(path, false)
	result, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	total := result.Summary.HighSeverity + result.Summary.MediumSeverity + result.Summary.LowSeverity + result.Summary.InfoSeverity
	if total != result.Summary.TotalIssues {
		t.Errorf("summary counts don't add up: %d+%d+%d+%d = %d, but TotalIssues = %d",
			result.Summary.HighSeverity, result.Summary.MediumSeverity,
			result.Summary.LowSeverity, result.Summary.InfoSeverity,
			total, result.Summary.TotalIssues)
	}
}

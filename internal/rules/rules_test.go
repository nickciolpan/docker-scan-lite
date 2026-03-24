package rules

import (
	"testing"
)

func TestNew(t *testing.T) {
	r := New()
	if r == nil {
		t.Fatal("New() returned nil")
	}
	if len(r.secretPatterns) == 0 {
		t.Error("secretPatterns not initialized")
	}
	if len(r.vulnerablePorts) == 0 {
		t.Error("vulnerablePorts not initialized")
	}
	if len(r.sensitiveEnvVars) == 0 {
		t.Error("sensitiveEnvVars not initialized")
	}
	if len(r.outdatedImages) == 0 {
		t.Error("outdatedImages not initialized")
	}
	if len(r.insecureCommands) == 0 {
		t.Error("insecureCommands not initialized")
	}
}

func TestIsVulnerablePort(t *testing.T) {
	r := New()

	tests := []struct {
		port     string
		expected bool
	}{
		{"22", true},
		{"23", true},
		{"3306", true},
		{"5432", true},
		{"6379", true},
		{"27017", true},
		{"9200", true},
		{"80", false},
		{"443", false},
		{"8080", false},
		{"3000", false},
		{"22/tcp", true},
		{"80/tcp", false},
	}

	for _, tt := range tests {
		t.Run(tt.port, func(t *testing.T) {
			if got := r.IsVulnerablePort(tt.port); got != tt.expected {
				t.Errorf("IsVulnerablePort(%q) = %v, want %v", tt.port, got, tt.expected)
			}
		})
	}
}

func TestIsSensitiveEnvVar(t *testing.T) {
	r := New()

	tests := []struct {
		name     string
		expected bool
	}{
		{"PASSWORD", true},
		{"DB_PASSWORD", true},
		{"API_KEY", true},
		{"SECRET_TOKEN", true},
		{"JWT_SECRET", true},
		{"AWS_ACCESS_KEY_ID", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"DATABASE_URL", true},
		{"GITHUB_TOKEN", true},
		{"MY_CUSTOM_PASSWORD", true},   // contains PASSWORD
		{"APP_SECRET_VALUE", true},     // contains SECRET
		{"AUTH_TOKEN_VALUE", true},     // contains TOKEN
		{"ENCRYPTION_KEY", true},      // contains KEY
		{"NODE_ENV", false},
		{"PATH", false},
		{"HOME", false},
		{"WORKDIR", false},
		{"APP_NAME", false},
		{"PORT", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.IsSensitiveEnvVar(tt.name); got != tt.expected {
				t.Errorf("IsSensitiveEnvVar(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestIsOutdatedBaseImage(t *testing.T) {
	r := New()

	tests := []struct {
		image    string
		tag      string
		expected bool
	}{
		{"ubuntu", "16.04", true},
		{"ubuntu", "14.04", true},
		{"ubuntu", "22.04", false},
		{"debian", "9", true},
		{"debian", "12", false},
		{"alpine", "3.5", true},
		{"alpine", "3.18", false},
		{"node", "8", true},
		{"node", "20", false},
		{"python", "2.7", true},
		{"python", "3.11", false},
		{"centos", "7", true},
		{"nginx", "1.14", true},
		{"nginx", "1.25", false},
		{"redis", "3", true},
		{"redis", "7", false},
		{"mysql", "5.6", true},
		{"mysql", "8", false},
	}

	for _, tt := range tests {
		t.Run(tt.image+":"+tt.tag, func(t *testing.T) {
			if got := r.IsOutdatedBaseImage(tt.image, tt.tag); got != tt.expected {
				t.Errorf("IsOutdatedBaseImage(%q, %q) = %v, want %v", tt.image, tt.tag, got, tt.expected)
			}
		})
	}
}

func TestHasInsecureCommand(t *testing.T) {
	r := New()

	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{"curl insecure", "RUN curl -k https://example.com", true},
		{"curl normal", "RUN curl https://example.com", false},
		{"wget no cert", "RUN wget --no-check-certificate https://example.com", true},
		{"wget normal", "RUN wget https://example.com", false},
		{"chmod 777", "RUN chmod 777 /app", true},
		{"chmod 755", "RUN chmod 755 /app", false},
		{"su root", "RUN su root -c 'echo hi'", true},
		{"sudo su", "RUN sudo su", true},
		{"ssh no host check", "RUN ssh -o StrictHostKeyChecking=no user@host", true},
		{"allow unauth", "RUN apt-get install --allow-unauthenticated pkg", true},
		{"normal apt", "RUN apt-get install -y curl", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.HasInsecureCommand(tt.command); got != tt.expected {
				t.Errorf("HasInsecureCommand(%q) = %v, want %v", tt.command, got, tt.expected)
			}
		})
	}
}

func TestHasUnpinnedPackages(t *testing.T) {
	r := New()

	tests := []struct {
		name     string
		command  string
		expected bool
	}{
		{"apt unpinned", "RUN apt-get install -y curl wget", true},
		{"apt pinned", "RUN apt-get install -y curl=7.68.0-1", false},
		{"apk unpinned", "RUN apk add curl", true},
		{"apk pinned", "RUN apk add curl=7.87.0-r0", false},
		{"pip unpinned", "RUN pip install requests flask", true},
		{"pip pinned", "RUN pip install requests==2.28.0", false},
		{"npm unpinned", "RUN npm install express", true},
		{"npm pinned", "RUN npm install express@4.18.2", false},
		{"yum unpinned", "RUN yum install httpd", true},
		{"no package mgr", "RUN echo hello", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := r.HasUnpinnedPackages(tt.command); got != tt.expected {
				t.Errorf("HasUnpinnedPackages(%q) = %v, want %v", tt.command, got, tt.expected)
			}
		})
	}
}

func TestFindSecrets(t *testing.T) {
	r := New()

	tests := []struct {
		name      string
		line      string
		wantTypes []string
		wantEmpty bool
	}{
		{
			name:      "AWS access key",
			line:      "ENV AWS_KEY=AKIAIOSFODNN7EXAMPLE",
			wantTypes: []string{"aws_access_key"},
		},
		{
			name:      "GitHub token",
			line:      "ENV TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
			wantTypes: []string{"github_token"},
		},
		{
			name:      "private key",
			line:      "RUN echo '-----BEGIN RSA PRIVATE KEY-----'",
			wantTypes: []string{"private_key"},
		},
		{
			name:      "database URL",
			line:      "ENV DB=postgresql://user:pass@host:5432/db",
			wantTypes: []string{"database_url"},
		},
		{
			name:      "plain HTTPS URL no false positive",
			line:      "RUN curl https://example.com/script.sh",
			wantEmpty: true,
		},
		{
			name:      "plain HTTP URL no false positive",
			line:      "ADD http://example.com/file.tar.gz /app/",
			wantEmpty: true,
		},
		{
			name:      "generic password",
			line:      "ENV PASSWORD=mysecretpassword123",
			wantTypes: []string{"generic_password"},
		},
		{
			name:      "no secrets",
			line:      "RUN echo hello world",
			wantEmpty: true,
		},
		{
			name:      "slack token",
			line:      "ENV SLACK=xoxb-1234567890-abcdefghij",
			wantTypes: []string{"slack_token"},
		},
		{
			name:      "JWT token",
			line:      "ENV JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
			wantTypes: []string{"jwt_token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets := r.FindSecrets(tt.line)
			if tt.wantEmpty {
				if len(secrets) != 0 {
					types := make([]string, len(secrets))
					for i, s := range secrets {
						types[i] = s.Type
					}
					t.Errorf("FindSecrets(%q) returned %v, want empty", tt.line, types)
				}
				return
			}
			if len(secrets) == 0 {
				t.Errorf("FindSecrets(%q) returned no secrets, want %v", tt.line, tt.wantTypes)
				return
			}
			foundTypes := map[string]bool{}
			for _, s := range secrets {
				foundTypes[s.Type] = true
			}
			for _, wantType := range tt.wantTypes {
				if !foundTypes[wantType] {
					t.Errorf("FindSecrets(%q) missing type %q, got types: %v", tt.line, wantType, foundTypes)
				}
			}
		})
	}
}

func TestFindSecretsNoFalsePositiveURLs(t *testing.T) {
	r := New()

	urls := []string{
		"RUN curl https://example.com/script.sh",
		"ADD https://github.com/user/repo/archive/main.tar.gz /app/",
		"RUN wget https://nodejs.org/dist/v18.0.0/node-v18.0.0-linux-x64.tar.xz",
		"RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash",
		"ADD http://archive.ubuntu.com/ubuntu/pool/main/file.deb /tmp/",
		"RUN curl https://get.docker.com | sh",
	}

	for _, url := range urls {
		secrets := r.FindSecrets(url)
		for _, s := range secrets {
			if s.Type == "database_url" {
				t.Errorf("False positive database_url for %q: matched %q", url, s.Value)
			}
		}
	}
}

func TestSecretSeverity(t *testing.T) {
	r := New()

	// Private keys should be high severity
	secrets := r.FindSecrets("-----BEGIN RSA PRIVATE KEY-----")
	for _, s := range secrets {
		if s.Type == "private_key" && s.Severity != "high" {
			t.Errorf("private_key should be high severity, got %q", s.Severity)
		}
	}

	// AWS keys should be high severity
	secrets = r.FindSecrets("AKIAIOSFODNN7EXAMPLE")
	for _, s := range secrets {
		if s.Type == "aws_access_key" && s.Severity != "high" {
			t.Errorf("aws_access_key should be high severity, got %q", s.Severity)
		}
	}
}

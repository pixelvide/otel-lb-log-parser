package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseLogLine(t *testing.T) {
	tests := []struct {
		name        string
		line        string
		wantErr     bool
		wantType    string
		wantMethod  string
		wantStatus  int
		wantClient  string
	}{
		{
			name: "Valid HTTP log",
			line: `http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0" - - arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "www.example.com" "-" 100 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"`,
			wantErr:    false,
			wantType:   "http",
			wantMethod: "GET",
			wantStatus: 200,
			wantClient: "192.168.131.39",
		},
		{
			name: "Valid HTTPS log",
			line: `https 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET https://www.example.com:443/ HTTP/1.1" "Mozilla/5.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "www.example.com" "arn:aws:acm:us-east-2:123456789012:certificate/12345678-1234-1234-1234-123456789012" 100 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"`,
			wantErr:    false,
			wantType:   "https",
			wantMethod: "GET",
			wantStatus: 200,
			wantClient: "192.168.131.39",
		},
		{
			name:    "Empty line",
			line:    "",
			wantErr: false,
		},
		{
			name:    "Comment line",
			line:    "#Version: 1.0",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := ParseLogLine(tt.line)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseLogLine() expected error, got none")
				}
				return
			}

			if err != nil {
				t.Errorf("ParseLogLine() unexpected error: %v", err)
				return
			}

			if tt.line == "" || tt.line[0] == '#' {
				if entry != nil {
					t.Errorf("ParseLogLine() expected nil for empty/comment line, got %+v", entry)
				}
				return
			}

			if entry == nil {
				t.Errorf("ParseLogLine() returned nil entry")
				return
			}

			if entry.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", entry.Type, tt.wantType)
			}

			if entry.RequestVerb != tt.wantMethod {
				t.Errorf("RequestVerb = %v, want %v", entry.RequestVerb, tt.wantMethod)
			}

			if entry.ELBStatusCode != tt.wantStatus {
				t.Errorf("ELBStatusCode = %v, want %v", entry.ELBStatusCode, tt.wantStatus)
			}

			if entry.ClientIP != tt.wantClient {
				t.Errorf("ClientIP = %v, want %v", entry.ClientIP, tt.wantClient)
			}
		})
	}
}

func TestParseLogFile(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.log")

	testData := `http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0" - - arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "www.example.com" "-" 100 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"
https 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET https://www.example.com:443/ HTTP/1.1" "Mozilla/5.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "www.example.com" "arn:aws:acm:us-east-2:123456789012:certificate/12345678-1234-1234-1234-123456789012" 100 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"
`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	entries, err := ParseLogFile(testFile)
	if err != nil {
		t.Fatalf("ParseLogFile() error = %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("ParseLogFile() returned %d entries, want 2", len(entries))
	}

	// Check first entry
	if entries[0].Type != "http" {
		t.Errorf("First entry Type = %v, want http", entries[0].Type)
	}

	// Check second entry
	if entries[1].Type != "https" {
		t.Errorf("Second entry Type = %v, want https", entries[1].Type)
	}
}

func BenchmarkParseLogLine(b *testing.B) {
	line := `http 2018-07-02T22:23:00.186641Z app/my-loadbalancer/50dc6c495c0c9188 192.168.131.39:2817 10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.46.0" - - arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "www.example.com" "-" 100 2018-07-02T22:22:48.364000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseLogLine(line)
	}
}

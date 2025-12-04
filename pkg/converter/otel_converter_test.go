package converter

import (
	"testing"

	"github.com/pixelvide/go-alb-processor/pkg/parser"
)

func TestParseTraceID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid trace ID",
			input:    "Root=1-58337262-36d228ad5d99923122bbe354",
			expected: "5833726236d228ad5d99923122bbe354",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Dash",
			input:    "-",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseTraceID(tt.input)
			if result != tt.expected {
				t.Errorf("ParseTraceID(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseRequestURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want map[string]string
	}{
		{
			name: "HTTPS URL with query",
			url:  "https://example.com:443/api/test?foo=bar",
			want: map[string]string{
				"http.scheme":  "https",
				"url.path":     "/api/test",
				"url.query":    "foo=bar",
				"http.target":  "/api/test?foo=bar",
			},
		},
		{
			name: "HTTP URL without query",
			url:  "http://example.com:80/",
			want: map[string]string{
				"http.scheme": "http",
				"url.path":    "/",
				"http.target": "/",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseRequestURL(tt.url)
			for k, v := range tt.want {
				if result[k] != v {
					t.Errorf("ParseRequestURL()[%q] = %q, want %q", k, result[k], v)
				}
			}
		})
	}
}

func TestConvertToOTel(t *testing.T) {
	entry := &parser.ALBLogEntry{
		Type:                   "h2",
		Time:                   "2025-12-04T00:55:01.294082Z",
		ELB:                    "app/test/12345",
		ClientIP:               "192.168.1.1",
		ClientPort:             12345,
		TargetIP:               "10.0.0.1",
		TargetPort:             80,
		RequestProcessingTime:  0.001,
		TargetProcessingTime:   0.010,
		ResponseProcessingTime: 0.001,
		ELBStatusCode:          200,
		TargetStatusCode:       "200",
		ReceivedBytes:          100,
		SentBytes:              500,
		RequestVerb:            "GET",
		RequestURL:             "https://example.com:443/api/test",
		RequestProto:           "HTTP/2.0",
		UserAgent:              "TestAgent/1.0",
		SSLCipher:              "ECDHE-RSA-AES128-GCM-SHA256",
		SSLProtocol:            "TLSv1.2",
		TargetGroupARN:         "arn:aws:elasticloadbalancing:us-east-1:123456:targetgroup/test/abc",
		TraceID:                "Root=1-58337262-36d228ad5d99923122bbe354",
		DomainName:             "example.com",
	}

	record := ConvertToOTel(entry)

	// Verify basic fields
	if record.SeverityText != "INFO" {
		t.Errorf("SeverityText = %q, want INFO", record.SeverityText)
	}

	if record.SeverityNumber != 9 {
		t.Errorf("SeverityNumber = %d, want 9", record.SeverityNumber)
	}

	if record.TraceID != "5833726236d228ad5d99923122bbe354" {
		t.Errorf("TraceID = %q, want 5833726236d228ad5d99923122bbe354", record.TraceID)
	}

	// Verify some attributes exist
	foundMethod := false
	for _, attr := range record.Attributes {
		if attr.Key == "http.request.method" && attr.Value.StringValue != nil && *attr.Value.StringValue == "GET" {
			foundMethod = true
			break
		}
	}

	if !foundMethod {
		t.Error("http.request.method attribute not found or incorrect")
	}
}

func TestExtractResourceAttributes(t *testing.T) {
	entry := &parser.ALBLogEntry{
		TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc",
	}

	attrs := ExtractResourceAttributes(entry)

	// Verify we have at least base attributes
	if len(attrs) < 3 {
		t.Errorf("Expected at least 3 resource attributes, got %d", len(attrs))
	}

	// Verify cloud.provider exists
	foundProvider := false
	for _, attr := range attrs {
		if attr.Key == "cloud.provider" && attr.Value.StringValue != nil && *attr.Value.StringValue == "aws" {
			foundProvider = true
			break
		}
	}

	if !foundProvider {
		t.Error("cloud.provider attribute not found")
	}
}

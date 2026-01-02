package converter

import (
	"encoding/json"
	"testing"

	"github.com/pixelvide/otel-aws-log-parser/pkg/parser"
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
				"http.scheme": "https",
				"url.path":    "/api/test",
				"url.query":   "foo=bar",
				"http.target": "/api/test?foo=bar",
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

	// Verify aws.alb.response_processing_time
	foundRespTime := false
	for _, attr := range record.Attributes {
		if attr.Key == "aws.alb.response_processing_time" && attr.Value.DoubleValue != nil && *attr.Value.DoubleValue == 0.001 {
			foundRespTime = true
			break
		}
	}
	if !foundRespTime {
		t.Error("aws.alb.response_processing_time attribute not found or incorrect")
	}

	// Verify aws.lb.name is NOT present (moved to Resource)
	for _, attr := range record.Attributes {
		if attr.Key == "aws.lb.name" {
			t.Error("Found unexpected attribute in Log Record: aws.lb.name")
		}
	}
}

func TestExtractResourceAttributes(t *testing.T) {
	entry := &parser.ALBLogEntry{
		TargetGroupARN: "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/test/abc",
		ELB:            "my-load-balancer",
	}

	attrs := ExtractResourceAttributes(entry)

	// Verify we have at least base attributes + lb name + cloud attributes
	// Provider, Platform, Service, LBName, Region, Account = 6
	if len(attrs) < 6 {
		t.Errorf("Expected at least 6 resource attributes, got %d", len(attrs))
	}

	// Verify cloud.provider exists
	foundProvider := false
	foundLBName := false
	foundCloudService := false
	for _, attr := range attrs {
		if attr.Key == "cloud.provider" && attr.Value.StringValue != nil && *attr.Value.StringValue == "aws" {
			foundProvider = true
		}
		if attr.Key == "aws.lb.name" && attr.Value.StringValue != nil && *attr.Value.StringValue == "my-load-balancer" {
			foundLBName = true
		}
		if attr.Key == "cloud.service" && attr.Value.StringValue != nil && *attr.Value.StringValue == "elasticloadbalancing" {
			foundCloudService = true
		}
	}

	if !foundProvider {
		t.Error("cloud.provider attribute not found")
	}
	if !foundLBName {
		t.Error("aws.lb.name attribute not found in Resource Attributes")
	}
	if !foundCloudService {
		t.Error("cloud.service attribute not found in Resource Attributes")
	}
}

func TestConvertWAFToOTel_ProcessedRules(t *testing.T) {
	entry := &parser.WAFLogEntry{
		Timestamp:         1609459200000,
		Action:            "BLOCK",
		TerminatingRuleID: "TerminatingRule",
		NonTerminatingMatchingRules: []parser.NonTerminatingRule{
			{RuleID: "NonTerminatingRule1", Action: "COUNT"},
		},
		RuleGroupList: []parser.RuleGroup{
			{
				TerminatingRule: &parser.RuleGroupRule{RuleID: "GroupTerminatingRule", Action: "BLOCK"},
				NonTerminatingRules: []parser.RuleGroupRule{
					{RuleID: "GroupNonTerminatingRule", Action: "COUNT"},
				},
			},
		},
		HTTPRequest: parser.HTTPRequest{
			HTTPMethod: "GET",
			URI:        "/",
			RequestID:  "1-58337262-36d228ad5d99923122bbe354",
			Country:    "IN",
			Headers: []parser.Header{
				{Name: "Host", Value: "example.com"},
			},
		},
		Labels:                   []parser.Label{{Name: "awswaf:clientip:geo:country:IN"}},
		RequestBodySize:          21,
		RequestBodySizeInspected: 21,
		JA3Fingerprint:           "f79b6bad2ad0641e1921aef10262856b",
		JA4Fingerprint:           "t13d1513h2_8daaf6152771_eca864cca44a",
	}

	record := ConvertWAFToOTel(entry)

	// Verify TraceID is extracted correctly from RequestID
	if record.TraceID != "5833726236d228ad5d99923122bbe354" {
		t.Errorf("TraceID = %q, want 5833726236d228ad5d99923122bbe354", record.TraceID)
	}

	// Verify new attributes
	expectedAttrs := map[string]string{
		"client.geo.country_iso_code": "IN",
		"aws.waf.labels":              `["awswaf:clientip:geo:country:IN"]`,
		"tls.client.ja3":              "f79b6bad2ad0641e1921aef10262856b",
		"tls.client.ja4":              "t13d1513h2_8daaf6152771_eca864cca44a",
	}

	for k, v := range expectedAttrs {
		found := false
		for _, attr := range record.Attributes {
			if attr.Key == k && attr.Value.StringValue != nil && *attr.Value.StringValue == v {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Attribute %q = %q not found", k, v)
		}
	}

	var processedRulesAttr *OTelAttribute
	for _, attr := range record.Attributes {
		if attr.Key == "aws.waf.processed_rules" {
			processedRulesAttr = &attr
			break
		}
	}

	if processedRulesAttr == nil {
		t.Fatal("aws.waf.processed_rules attribute not found")
	}

	if processedRulesAttr.Value.StringValue == nil {
		t.Fatal("aws.waf.processed_rules value is nil")
	}

	jsonValue := *processedRulesAttr.Value.StringValue
	var rules []ProcessedRule
	if err := json.Unmarshal([]byte(jsonValue), &rules); err != nil {
		t.Fatalf("Failed to unmarshal processed rules JSON: %v", err)
	}

	// Expect 4 rules: 1 Terminating + 1 NonTerminating + 1 GroupTerminating + 1 GroupNonTerminating
	if len(rules) != 4 {
		t.Errorf("Expected 4 processed rules, got %d", len(rules))
	}

	// Verify specific rule presence
	ruleMap := make(map[string]ProcessedRule)
	for _, r := range rules {
		ruleMap[r.RuleID] = r
	}

	if r, ok := ruleMap["TerminatingRule"]; !ok || r.Type != "TERMINATING" {
		t.Error("TerminatingRule missing or incorrect type")
	}
	if r, ok := ruleMap["NonTerminatingRule1"]; !ok || r.Type != "NON_TERMINATING" {
		t.Error("NonTerminatingRule1 missing or incorrect type")
	}
	if r, ok := ruleMap["GroupTerminatingRule"]; !ok || r.Type != "GROUP_TERMINATING" {
		t.Error("GroupTerminatingRule missing or incorrect type")
	}
	if r, ok := ruleMap["GroupNonTerminatingRule"]; !ok || r.Type != "GROUP_NON_TERMINATING" {
		t.Error("GroupNonTerminatingRule missing or incorrect type")
	}

	// Verify that cloud.* attributes are NOT present (should be in Resource, not Log Record)
	for _, attr := range record.Attributes {
		if attr.Key == "cloud.provider" || attr.Key == "cloud.platform" || attr.Key == "service.name" {
			t.Errorf("Found unexpected attribute in Log Record: %s", attr.Key)
		}
	}
}

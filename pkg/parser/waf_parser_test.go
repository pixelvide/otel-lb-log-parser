package parser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseWAFLogFile(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "waf_test.log")

	// Sample data from AWS documentation (rate based rule blocks)
	testData := `
{ "timestamp":1683355579981, "formatVersion":1, "webaclId": "arn:aws:wafv2:eu-west-3:111122223333:regional/webacl/TEST-WEBACL/123", "terminatingRuleId":"RateBasedRule", "terminatingRuleType":"RATE_BASED", "action":"BLOCK", "terminatingRuleMatchDetails":[], "httpSourceName":"APIGW", "httpSourceId":"EXAMPLE11:rjvegx5guh:CanaryTest", "ruleGroupList":[], "rateBasedRuleList":[ { "rateBasedRuleId": "123", "rateBasedRuleName":"RateBasedRule", "limitKey":"CUSTOMKEYS", "maxRateAllowed":100, "evaluationWindowSec":"120", "customValues":[ { "key":"HEADER", "name":"dogname", "value":"ella" } ] } ], "nonTerminatingMatchingRules":[], "httpRequest":{ "clientIp":"52.46.82.45", "country":"FR", "headers":[ { "name":"X-Forwarded-For", "value":"52.46.82.45" }, { "name":"X-Forwarded-Proto", "value":"https" }, { "name":"Host", "value":"example.com" } ], "uri":"/CanaryTest", "args":"", "httpVersion":"HTTP/1.1", "httpMethod":"GET", "requestId":"Ed0AiHF_CGYF-DA=" } }
{ "timestamp":1683355580000, "formatVersion":1, "webaclId": "arn:aws:wafv2:eu-west-3:111122223333:regional/webacl/TEST-WEBACL/123", "terminatingRuleId":"Default_Action", "terminatingRuleType":"REGULAR", "action":"ALLOW", "terminatingRuleMatchDetails":[], "httpSourceName":"APIGW", "httpSourceId":"EXAMPLE11:rjvegx5guh:CanaryTest", "ruleGroupList":[], "httpRequest":{ "clientIp":"1.2.3.4", "country":"US", "headers":[], "uri":"/valid", "args":"", "httpVersion":"HTTP/1.1", "httpMethod":"GET", "requestId":"request-2" } }
`

	if err := os.WriteFile(testFile, []byte(testData), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	entries, err := ParseWAFLogFile(testFile)
	if err != nil {
		t.Fatalf("ParseWAFLogFile() error = %v", err)
	}

	if len(entries) != 2 {
		t.Errorf("ParseWAFLogFile() returned %d entries, want 2", len(entries))
	}

	// Check first entry
	if entries[0].Action != "BLOCK" {
		t.Errorf("First entry Action = %v, want BLOCK", entries[0].Action)
	}
	if entries[0].HTTPRequest.ClientIP != "52.46.82.45" {
		t.Errorf("First entry ClientIP = %v, want 52.46.82.45", entries[0].HTTPRequest.ClientIP)
	}

	// Check second entry
	if entries[1].Action != "ALLOW" {
		t.Errorf("Second entry Action = %v, want ALLOW", entries[1].Action)
	}
	if entries[1].HTTPRequest.ClientIP != "1.2.3.4" {
		t.Errorf("Second entry ClientIP = %v, want 1.2.3.4", entries[1].HTTPRequest.ClientIP)
	}
}

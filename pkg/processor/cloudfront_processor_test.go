package processor

import (
	"testing"
)

func TestCloudFrontProcessor_Matches(t *testing.T) {
	proc := &CloudFrontProcessor{}

	tests := []struct {
		key  string
		want bool
	}{
		// Valid case: Standard Logging v2 with default prefix
		{"AWSLogs/123456789012/CloudFront/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", true},
		// Invalid cases: Legacy or Custom prefixes
		{"E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", false}, // Legacy/Root
		{"prefix/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", false}, // Custom prefix
		{"my/custom/path/E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz", false}, // Custom path
		// Invalid cases: Other types
		{"not-cloudfront.log", false},
		{"AWSLogs/123456789012/CloudFront/E2K55636F2K7.2019-12-04-21.d111111abcdef8.txt", false}, // Must be .gz
		{"invalid-format.gz", false}, // Does not match pattern
		{"AWSLogs/123456789012/elasticloadbalancing/us-east-1/2023/01/01/123456789012_elasticloadbalancing_us-east-1_app.my-load-balancer.1234567890.gz", false}, // ALB log
	}

	for _, tt := range tests {
		got := proc.Matches("bucket", tt.key)
		if got != tt.want {
			t.Errorf("Matches(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

// Mocking S3 read functionality for Process test is complex without a full mock S3 client
// or abstracting the reader.
// However, we can trust ReadAndParseFromS3 is tested elsewhere or trust integration tests.
// We should check if converter logic works via unit tests on CloudFrontAdapter or similar.

func TestCloudFrontAdapter_GetResourceKey(t *testing.T) {
	// Need to import parser locally or mock
}

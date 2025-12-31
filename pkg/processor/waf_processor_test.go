package processor

import (
	"testing"
)

func TestWAFProcessor_Matches(t *testing.T) {
	proc := &WAFProcessor{}

	tests := []struct {
		name   string
		bucket string
		key    string
		want   bool
	}{
		{
			name:   "User provided format",
			bucket: "aws-waf-logs-test",
			key:    "KEY-NAME-PREFIX/AWSLogs/123456789012/WAFLogs/us-east-1/TEST-WEBACL/2023/01/01/00/00/123456789012_waflogs_us-east-1_TEST-WEBACL_20230101T0000Z_hash.log.gz",
			want:   true,
		},
		{
			name:   "Standard WAFLogs path",
			bucket: "my-bucket",
			key:    "AWSLogs/123/WAFLogs/us-east-1/my-acl/123_waflogs_file.log",
			want:   true,
		},
		{
			name:   "Alternative prefix with correct format",
			bucket: "my-bucket",
			key:    "some/prefix/WAFLogs/us-east-1/my-acl/123_waflogs_file.log",
			want:   true,
		},
		{
			name:   "ALB log",
			bucket: "my-bucket",
			key:    "AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_app.my-lb.123_20230101T0000Z_1.2.3.4_5678.log.gz",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proc.Matches(tt.bucket, tt.key); got != tt.want {
				t.Errorf("WAFProcessor.Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

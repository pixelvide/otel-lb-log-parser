package processor_test

import (
	"testing"

	"github.com/pixelvide/otel-lb-log-parser/pkg/processor"
)

func TestProcessorMatching(t *testing.T) {
	albProc := &processor.ALBProcessor{}
	nlbProc := &processor.NLBProcessor{}

	tests := []struct {
		name    string
		key     string
		wantALB bool
		wantNLB bool
	}{
		{
			name:    "User provided NLB format",
			key:     "bucket/prefix/AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_net.my-lb.123_20230101T0000Z_123.log.gz",
			wantALB: false,
			wantNLB: true,
		},
		{
			name:    "User provided ALB format",
			key:     "bucket/prefix/AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_app.my-lb.123_20230101T0000Z_1.2.3.4_123.log.gz",
			wantALB: true,
			wantNLB: false,
		},
		{
			name:    "Standard NLB without prefix",
			key:     "AWSLogs/123/elasticloadbalancing/us-east-1/2023/01/01/123_elasticloadbalancing_us-east-1_net.my-lb.123_20230101T0000Z_hash.log.gz",
			wantALB: false,
			wantNLB: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := albProc.Matches("bucket", tt.key); got != tt.wantALB {
				t.Errorf("ALBProcessor.Matches() = %v, want %v", got, tt.wantALB)
			}
			if got := nlbProc.Matches("bucket", tt.key); got != tt.wantNLB {
				t.Errorf("NLBProcessor.Matches() = %v, want %v", got, tt.wantNLB)
			}
		})
	}
}

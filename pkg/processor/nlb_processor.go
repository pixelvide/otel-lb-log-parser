package processor

import (
	"context"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pixelvide/otel-lb-log-parser/cmd/lambda/adapter"
	"github.com/pixelvide/otel-lb-log-parser/pkg/converter"
	"github.com/pixelvide/otel-lb-log-parser/pkg/parser"
)

type NLBProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
}

func (p *NLBProcessor) Name() string {
	return "NLB"
}

func (p *NLBProcessor) Matches(bucket, key string) bool {
	return strings.Contains(key, "/elasticloadbalancing/") && strings.Contains(key, "_net.")
}

func (p *NLBProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.S3, bucket, key string) ([]adapter.LogAdapter, error) {
	return ReadAndParseFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(line string) (adapter.LogAdapter, error) {
		entry, err := parser.ParseNLBLogLine(line)
		if err != nil {
			return nil, err
		}
		return NLBAdapter{entry}, nil
	})
}

// NLBAdapter implementation
type NLBAdapter struct {
	*parser.NLBLogEntry
}

func (a NLBAdapter) GetResourceKey() string {
	arn := a.NLBLogEntry.ChosenCertARN
	if arn == "" || arn == "-" {
		// Fallback to ListenerID or ELB name
		arn = a.NLBLogEntry.ListenerID // often contains ARN
	}
	return arn
}

func (a NLBAdapter) GetResourceAttributes() []converter.OTelAttribute {
	return converter.ExtractResourceAttributesNLB(a.NLBLogEntry)
}

func (a NLBAdapter) ToOTel() converter.OTelLogRecord {
	return converter.ConvertNLBToOTel(a.NLBLogEntry)
}

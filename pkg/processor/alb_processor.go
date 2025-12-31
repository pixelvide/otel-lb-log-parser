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

type ALBProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
}

func (p *ALBProcessor) Name() string {
	return "ALB"
}

func (p *ALBProcessor) Matches(bucket, key string) bool {
	return strings.Contains(key, "/elasticloadbalancing/") && strings.Contains(key, "_app.")
}

func (p *ALBProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.S3, bucket, key string) ([]adapter.LogAdapter, error) {
	return ReadAndParseFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(line string) (adapter.LogAdapter, error) {
		entry, err := parser.ParseLogLine(line)
		if err != nil {
			return nil, err
		}
		return ALBAdapter{entry}, nil
	})
}

// ALBAdapter implementation
type ALBAdapter struct {
	*parser.ALBLogEntry
}

func (a ALBAdapter) GetResourceKey() string {
	arn := a.ALBLogEntry.TargetGroupARN
	if arn == "" || arn == "-" {
		arn = a.ALBLogEntry.ChosenCertARN
	}
	return arn
}

func (a ALBAdapter) GetResourceAttributes() []converter.OTelAttribute {
	return converter.ExtractResourceAttributes(a.ALBLogEntry)
}

func (a ALBAdapter) ToOTel() converter.OTelLogRecord {
	return converter.ConvertToOTel(a.ALBLogEntry)
}

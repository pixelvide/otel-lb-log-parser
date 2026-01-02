package processor

import (
	"context"
	"log/slog"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pixelvide/otel-aws-log-parser/cmd/lambda/adapter"
	"github.com/pixelvide/otel-aws-log-parser/pkg/converter"
	"github.com/pixelvide/otel-aws-log-parser/pkg/parser"
)

// Regex for CloudFront log filename
// Format: {DistributionID}.{YYYY}-{MM}-{DD}-{HH}.{UniqueID}.gz
// Example: E2K55636F2K7.2019-12-04-21.d111111abcdef8.gz
// We'll use a relatively loose pattern to capture the structure.
// Distribution ID is usually alphanumeric.
var cloudFrontLogPattern = regexp.MustCompile(`[A-Z0-9]+\.\d{4}-\d{2}-\d{2}-\d{2}\.[a-zA-Z0-9]+\.gz$`)

type CloudFrontProcessor struct {
	MaxBatchSize  int
	MaxConcurrent int
}

func (p *CloudFrontProcessor) Name() string {
	return "CloudFront"
}

func (p *CloudFrontProcessor) Matches(bucket, key string) bool {
	// Only match standard logging (v2) with default prefix structure:
	// AWSLogs/{account-id}/CloudFront/{distribution-id}.{date}.{unique-id}.gz
	// We strictly require "AWSLogs/" prefix and "/CloudFront/" segment to avoid
	// processing legacy logs or custom prefixes as requested.
	return strings.HasPrefix(key, "AWSLogs/") &&
		strings.Contains(key, "/CloudFront/") &&
		strings.HasSuffix(key, ".gz") &&
		cloudFrontLogPattern.MatchString(key)
}

func (p *CloudFrontProcessor) Process(ctx context.Context, logger *slog.Logger, s3Client *s3.S3, bucket, key string) ([]adapter.LogAdapter, error) {
	// Attempt to parse account/region if they happen to be in the path (unlikely for standard CF logs, but harmless)
	accountID, region := ParseRegionAccountFromS3Key(key)

	return ReadAndParseFromS3(logger, s3Client, bucket, key, p.MaxBatchSize, p.MaxConcurrent, func(line string) (adapter.LogAdapter, error) {
		entry, err := parser.ParseCloudFrontLogLine(line)
		if err != nil {
			return nil, err
		}
		// If entry is nil (comment line), ReadAndParseFromS3 handles it if we return nil, nil?
		// Looking at ALBProcessor: parser.ParseLogLine returns nil, nil for comments.
		// CloudFront parser behaves similarly.
		if entry == nil {
			return nil, nil
		}

		return CloudFrontAdapter{
			CloudFrontLogEntry: entry,
			AccountID:          accountID,
			Region:             region,
		}, nil
	})
}

// CloudFrontAdapter implementation
type CloudFrontAdapter struct {
	*parser.CloudFrontLogEntry
	AccountID string
	Region    string
}

func (a CloudFrontAdapter) GetResourceKey() string {
	// Use distribution domain as key resource identifier
	return a.CloudFrontLogEntry.CSHost
}

func (a CloudFrontAdapter) GetResourceAttributes() []converter.OTelAttribute {
	attrs := converter.ExtractResourceAttributesCloudFront(a.CloudFrontLogEntry)

	// If we managed to extract account/region from path (rare), add them
	hasAccount := false
	hasRegion := false
	for _, attr := range attrs {
		if attr.Key == "cloud.account.id" {
			hasAccount = true
		}
		if attr.Key == "cloud.region" {
			hasRegion = true
		}
	}

	if !hasAccount && a.AccountID != "" {
		attrs = append(attrs, converter.OTelAttribute{Key: "cloud.account.id", Value: converter.OTelAnyValue{StringValue: &a.AccountID}})
	}
	if !hasRegion && a.Region != "" {
		attrs = append(attrs, converter.OTelAttribute{Key: "cloud.region", Value: converter.OTelAnyValue{StringValue: &a.Region}})
	}

	return attrs
}

func (a CloudFrontAdapter) ToOTel() converter.OTelLogRecord {
	return converter.ConvertCloudFrontToOTel(a.CloudFrontLogEntry)
}

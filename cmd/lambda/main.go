package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	"github.com/pixelvide/otel-aws-log-parser/cmd/lambda/adapter"
	"github.com/pixelvide/otel-aws-log-parser/pkg/converter"
	"github.com/pixelvide/otel-aws-log-parser/pkg/processor"
)

var (
	s3Client      *s3.S3
	otlpEndpoint  string
	basicAuthUser string
	basicAuthPass string
	maxBatchSize  int
	maxRetries    int
	retryBaseSec  float64
	logger        *slog.Logger
	maxConcurrent int
	registry      *processor.Registry
)

func init() {
	// Initialize structured logger (JSON format)
	logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Initialize AWS session
	sess := session.Must(session.NewSession())
	s3Client = s3.New(sess)

	// Load configuration from environment
	otlpEndpoint = getEnv("SIGNOZ_OTLP_ENDPOINT", "http://localhost:4318/v1/logs")
	basicAuthUser = os.Getenv("BASIC_AUTH_USERNAME")
	basicAuthPass = os.Getenv("BASIC_AUTH_PASSWORD")
	maxBatchSize = getEnvInt("MAX_BATCH_SIZE", 500)
	maxRetries = getEnvInt("MAX_RETRIES", 3)
	maxConcurrent = getEnvInt("MAX_CONCURRENT", 10)
	retryBaseSec = 1.0

	// Initialize Registry
	registry = processor.NewRegistry()
	registry.Register(&processor.ALBProcessor{MaxBatchSize: maxBatchSize, MaxConcurrent: maxConcurrent})
	registry.Register(&processor.NLBProcessor{MaxBatchSize: maxBatchSize, MaxConcurrent: maxConcurrent})
	registry.Register(&processor.CloudFrontProcessor{MaxBatchSize: maxBatchSize, MaxConcurrent: maxConcurrent})
	registry.Register(&processor.WAFProcessor{})
}

func handler(ctx context.Context, sqsEvent events.SQSEvent) (events.SQSEventResponse, error) {
	response := events.SQSEventResponse{
		BatchItemFailures: []events.SQSBatchItemFailure{},
	}

	var allEntries []adapter.LogAdapter

	logger.Info("Lambda triggered", "sqs_record_count", len(sqsEvent.Records))

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)

	for _, record := range sqsEvent.Records {
		wg.Add(1)
		go func(record events.SQSMessage) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Parse Body as S3 Event
			s3Records, err := parseBodyAsS3(logger, []byte(record.Body))
			if err != nil {
				logger.Warn("Failed to parse SQS body, skipping message", "message_id", record.MessageId, "error", err)
				return
			}

			// Usually one SQS message contains one S3 event (EventBridge wrapper)
			// But parseBodyAsS3 returns slice, so handle all
			msgFailed := false
			var recordEntries []adapter.LogAdapter

			for _, s3Record := range s3Records {
				bucket := s3Record.S3.Bucket.Name
				key := s3Record.S3.Object.Key

				if bucket == "" || key == "" {
					logger.Warn("Skipping record with empty bucket or key", "message_id", record.MessageId)
					continue
				}

				log := logger.With("bucket", bucket, "key", key, "message_id", record.MessageId)
				log.Info("Processing S3 object")

				// Find matching processor
				proc := registry.Find(bucket, key)
				if proc == nil {
					log.Info("Skipping object: no matching processor found")
					continue
				}

				// Process logs
				entries, err := proc.Process(ctx, logger, s3Client, bucket, key)
				if err != nil {
					log.Error("Error processing S3 object", "error", err)
					msgFailed = true
					break // Stop processing this SQS message, mark as failed
				}

				if len(entries) > 0 {
					recordEntries = append(recordEntries, entries...)
				}
			}

			mu.Lock()
			defer mu.Unlock()

			if msgFailed {
				response.BatchItemFailures = append(response.BatchItemFailures, events.SQSBatchItemFailure{
					ItemIdentifier: record.MessageId,
				})
			} else if len(recordEntries) > 0 {
				allEntries = append(allEntries, recordEntries...)
			}
		}(record)
	}

	wg.Wait()

	// Send successful entries to OTLP
	if len(allEntries) > 0 {
		logger.Info("Sending collected entries to OTLP", "count", len(allEntries))
		if err := convertAndSend(allEntries); err != nil {
			logger.Error("Error sending to OTLP", "error", err)
			return response, err // Returning error triggers full batch failure usually, which is what we want if backend is down
		}
	}

	logger.Info("Lambda execution completed", "failures", len(response.BatchItemFailures))
	return response, nil
}

func parseBodyAsS3(logger *slog.Logger, body []byte) ([]events.S3EventRecord, error) {
	// Try EventBridge S3 Event (common in SQS)
	var ebEvent EventBridgeS3Event
	if err := json.Unmarshal(body, &ebEvent); err == nil {
		if ebEvent.Source == "aws.s3" && ebEvent.Detail.Bucket.Name != "" {
			return []events.S3EventRecord{{
				S3: events.S3Entity{
					Bucket: events.S3Bucket{Name: ebEvent.Detail.Bucket.Name},
					Object: events.S3Object{Key: ebEvent.Detail.Object.Key},
				},
				AWSRegion: ebEvent.Region,
			}}, nil
		}
	}

	return nil, fmt.Errorf("body does not match EventBridge S3 format")
}

// EventBridgeS3Event structure for S3 events via EventBridge
type EventBridgeS3Event struct {
	Source     string `json:"source"`
	DetailType string `json:"detail-type"`
	Region     string `json:"region"`
	Detail     struct {
		Bucket struct {
			Name string `json:"name"`
		} `json:"bucket"`
		Object struct {
			Key string `json:"key"`
		} `json:"object"`
	} `json:"detail"`
}

func convertAndSend(entries []adapter.LogAdapter) error {
	// Group by resource
	grouped := make(map[string]*resourceGroup)

	for _, entry := range entries {
		resKey := entry.GetResourceKey()

		if _, exists := grouped[resKey]; !exists {
			grouped[resKey] = &resourceGroup{
				ResourceAttrs: entry.GetResourceAttributes(),
				LogRecords:    []converter.OTelLogRecord{},
			}
		}

		logRecord := entry.ToOTel()
		grouped[resKey].LogRecords = append(grouped[resKey].LogRecords, logRecord)
	}

	logger.Info("Grouped logs", "resource_group_count", len(grouped))

	// Concurrency control
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	errChan := make(chan error, 1)

	totalSent := 0
	var sentLock sync.Mutex

	// Send each group in batches
	for resKey, group := range grouped {
		groupLog := logger.With("resource_key", resKey, "total_logs", len(group.LogRecords))
		groupLog.Info("Processing resource group")

		// Split into batches
		batchCount := 0
		for i := 0; i < len(group.LogRecords); i += maxBatchSize {
			// Check for previous errors
			select {
			case err := <-errChan:
				return err
			default:
			}

			end := i + maxBatchSize
			if end > len(group.LogRecords) {
				end = len(group.LogRecords)
			}

			batch := group.LogRecords[i:end]
			payload := buildPayload(group.ResourceAttrs, batch)
			currentBatchCount := batchCount + 1
			currentBatchSize := len(batch)

			wg.Add(1)
			go func(p converter.OTLPPayload, bID int, bSize int, log *slog.Logger) {
				defer wg.Done()

				// Acquire semaphore
				sem <- struct{}{}
				defer func() { <-sem }()

				log.Info("Sending batch", "batch_id", bID, "batch_size", bSize)

				if err := sendWithRetry(p); err != nil {
					log.Error("Failed to send batch", "batch_id", bID, "error", err)
					// Try to report error (non-blocking)
					select {
					case errChan <- fmt.Errorf("failed to send batch %d: %w", bID, err):
					default:
					}
					return
				}

				sentLock.Lock()
				totalSent += bSize
				sentLock.Unlock()
			}(payload, currentBatchCount, currentBatchSize, groupLog)

			batchCount++
		}
	}

	// Wait for all batches to complete
	wg.Wait()

	// Check for any errors that occurred
	select {
	case err := <-errChan:
		return err
	default:
	}

	logger.Info("Successfully sent all logs", "total_sent", totalSent, "resource_groups", len(grouped))
	return nil
}

func buildPayload(resourceAttrs []converter.OTelAttribute, logRecords []converter.OTelLogRecord) converter.OTLPPayload {
	return converter.OTLPPayload{
		ResourceLogs: []converter.ResourceLog{
			{
				Resource: converter.ResourceAttributes{
					Attributes: resourceAttrs,
				},
				ScopeLogs: []converter.ScopeLog{
					{
						Scope: converter.Scope{
							Name:    "otel-aws-log-parser",
							Version: "1.0.0",
						},
						LogRecords: logRecords,
					},
				},
			},
		},
	}
}

func sendWithRetry(payload converter.OTLPPayload) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			multiplier := 1 << uint(attempt-1)
			sleep := time.Duration(retryBaseSec*float64(multiplier)) * time.Second
			time.Sleep(sleep)
		}

		req, err := http.NewRequest("POST", otlpEndpoint, bytes.NewBuffer(body))
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")

		if basicAuthUser != "" && basicAuthPass != "" {
			req.SetBasicAuth(basicAuthUser, basicAuthPass)
		}

		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Batch send attempt failed", "attempt", attempt+1, "error", err)
			lastErr = err
			continue
		}

		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			logger.Info("Batch sent successfully", "attempt", attempt+1, "status", resp.StatusCode)
			return nil
		}

		respBody, _ := io.ReadAll(resp.Body)
		logger.Warn("Batch send attempt failed", "attempt", attempt+1, "status", resp.StatusCode, "response", string(respBody))
		lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return fmt.Errorf("failed after %d attempts: %w", maxRetries+1, lastErr)
}

type resourceGroup struct {
	ResourceAttrs []converter.OTelAttribute
	LogRecords    []converter.OTelLogRecord
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if result, err := strconv.Atoi(value); err == nil {
			return result
		}
	}
	return defaultValue
}

func main() {
	lambda.Start(handler)
}

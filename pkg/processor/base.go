package processor

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pixelvide/otel-lb-log-parser/cmd/lambda/adapter"
)

// ProcessLineFunc is a function that processes a single log line
type ProcessLineFunc func(line string) (adapter.LogAdapter, error)

// ReadAndParseFromS3 is a helper to stream and parse line-based logs
func ReadAndParseFromS3(logger *slog.Logger, s3Client *s3.S3, bucket, key string, maxBatchSize, maxConcurrent int, parseFunc ProcessLineFunc) ([]adapter.LogAdapter, error) {
	// Get object from S3
	result, err := s3Client.GetObject(&s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get S3 object: %w", err)
	}
	defer result.Body.Close()

	var reader io.Reader = result.Body

	// Handle gzip compression
	if strings.HasSuffix(key, ".gz") {
		gzReader, err := gzip.NewReader(result.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Create channels for parallel processing
	linesChan := make(chan string, maxBatchSize)
	entriesChan := make(chan adapter.LogAdapter, maxBatchSize)
	var wg sync.WaitGroup

	// Start workers
	numWorkers := maxConcurrent
	if numWorkers < 1 {
		numWorkers = 1
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range linesChan {
				if line == "" {
					continue
				}
				entry, err := parseFunc(line)
				if err == nil && entry != nil {
					entriesChan <- entry
				}
			}
		}()
	}

	// Start a goroutine to read lines and send to workers
	go func() {
		scanner := bufio.NewScanner(reader)
		// Increase buffer size
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			linesChan <- scanner.Text()
		}

		if err := scanner.Err(); err != nil {
			logger.Error("Error scanning S3 object", "error", err)
		}

		close(linesChan)
	}()

	// Start a goroutine to close entriesChan when all workers are done
	go func() {
		wg.Wait()
		close(entriesChan)
	}()

	// Collect results
	entries := make([]adapter.LogAdapter, 0)
	for entry := range entriesChan {
		entries = append(entries, entry)
	}

	logger.Info("Parsed entries", "count", len(entries))
	return entries, nil
}

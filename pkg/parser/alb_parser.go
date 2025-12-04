package parser

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// ALBLogEntry represents a parsed ALB log entry
type ALBLogEntry struct {
	Type                   string
	Time                   string
	ELB                    string
	ClientIP               string
	ClientPort             int
	TargetIP               string
	TargetPort             int
	RequestProcessingTime  float64
	TargetProcessingTime   float64
	ResponseProcessingTime float64
	ELBStatusCode          int
	TargetStatusCode       string
	ReceivedBytes          int64
	SentBytes              int64
	RequestVerb            string
	RequestURL             string
	RequestProto           string
	UserAgent              string
	SSLCipher              string
	SSLProtocol            string
	TargetGroupARN         string
	TraceID                string
	DomainName             string
	ChosenCertARN          string
	MatchedRulePriority    string
	RequestCreationTime    string
	ActionsExecuted        string
	RedirectURL            string
	LambdaErrorReason      string
	TargetPortList         string
	TargetStatusCodeList   string
	Classification         string
	ClassificationReason   string
	ConnTraceID            string
}

// Regex pattern matching Athena schema (same as Python implementation)
// Updated to handle optional trailing fields
var albLogPattern = regexp.MustCompile(
	`^([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) "([^ ]*) (.*) (- |[^ ]*)" "([^"]*)" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^"]*)" ([-.0-9]*) ([^ ]*) "([^"]*)" "([^"]*)" "([^ ]*)" "([^\s]+?)" "([^\s]+)" "([^ ]*)" "([^ ]*)" ([^ ]*)(?: "([^"]*)")?(?: "([^"]*)")?(?: "([^"]*)")?`,
)

// ParseLogLine parses a single ALB log line
func ParseLogLine(line string) (*ALBLogEntry, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	matches := albLogPattern.FindStringSubmatch(line)
	if matches == nil {
		return nil, fmt.Errorf("failed to parse log line")
	}

	entry := &ALBLogEntry{
		Type:                   getString(matches, 1),
		Time:                   getString(matches, 2),
		ELB:                    getString(matches, 3),
		ClientIP:               getString(matches, 4),
		ClientPort:             getInt(matches, 5),
		TargetIP:               getString(matches, 6),
		TargetPort:             getInt(matches, 7),
		RequestProcessingTime:  getFloat(matches, 8),
		TargetProcessingTime:   getFloat(matches, 9),
		ResponseProcessingTime: getFloat(matches, 10),
		ELBStatusCode:          getInt(matches, 11),
		TargetStatusCode:       getString(matches, 12),
		ReceivedBytes:          getInt64(matches, 13),
		SentBytes:              getInt64(matches, 14),
		RequestVerb:            getString(matches, 15),
		RequestURL:             getString(matches, 16),
		RequestProto:           getString(matches, 17),
		UserAgent:              getString(matches, 18),
		SSLCipher:              getString(matches, 19),
		SSLProtocol:            getString(matches, 20),
		TargetGroupARN:         getString(matches, 21),
		TraceID:                getString(matches, 22),
		DomainName:             getString(matches, 23),
		ChosenCertARN:          getString(matches, 24),
		MatchedRulePriority:    getString(matches, 25),
		RequestCreationTime:    getString(matches, 26),
		ActionsExecuted:        getString(matches, 27),
		RedirectURL:            getString(matches, 28),
		LambdaErrorReason:      getString(matches, 29),
		TargetPortList:         getString(matches, 30),
		TargetStatusCodeList:   getString(matches, 31),
		Classification:         getString(matches, 32),
		ClassificationReason:   getString(matches, 33),
		ConnTraceID:            getString(matches, 34),
	}

	return entry, nil
}

// ParseLogFile parses an ALB log file (supports gzip)
func ParseLogFile(filePath string) ([]*ALBLogEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file

	// Check if gzipped
	if strings.HasSuffix(filePath, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	}

	// Read all content
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	entries := make([]*ALBLogEntry, 0, len(lines))

	for _, line := range lines {
		entry, err := ParseLogLine(line)
		if err != nil {
			// Skip malformed lines
			continue
		}
		if entry != nil {
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// Helper functions
func getString(matches []string, index int) string {
	if index >= len(matches) {
		return ""
	}
	val := matches[index]
	if val == "-" {
		return ""
	}
	return val
}

func getInt(matches []string, index int) int {
	str := getString(matches, index)
	if str == "" {
		return 0
	}
	val, _ := strconv.Atoi(str)
	return val
}

func getInt64(matches []string, index int) int64 {
	str := getString(matches, index)
	if str == "" {
		return 0
	}
	val, _ := strconv.ParseInt(str, 10, 64)
	return val
}

func getFloat(matches []string, index int) float64 {
	str := getString(matches, index)
	if str == "" {
		return 0
	}
	val, _ := strconv.ParseFloat(str, 64)
	return val
}

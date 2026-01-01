package main

import (
	"encoding/json"
	"fmt"
	"os"

	"strings"

	"github.com/pixelvide/otel-lb-log-parser/cmd/lambda/adapter"
	"github.com/pixelvide/otel-lb-log-parser/pkg/converter"
	"github.com/pixelvide/otel-lb-log-parser/pkg/parser"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log-file-path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s /path/to/alb.log.gz\n", os.Args[0])
		os.Exit(1)
	}

	filePath := os.Args[1]
	var adapters []adapter.LogAdapter

	if strings.Contains(strings.ToLower(filePath), "waflogs") {
		fmt.Fprintf(os.Stderr, "Detected WAF log file\n")
		entries, err := parser.ParseWAFLogFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing WAF file: %v\n", err)
			os.Exit(1)
		}
		for _, e := range entries {
			adapters = append(adapters, wapAdapter{e})
		}
	} else if strings.Contains(strings.ToLower(filePath), "_net.") {
		fmt.Fprintf(os.Stderr, "Detected NLB log file\n")
		// NLB parser works line by line usually, need to read file
		// For demo simplicity, reuse ParseLogFile if it was generic, but it's not.
		// Let's implement simple file reading for NLB here or skip if too complex.
		// Actually, let's just implement WAF for now as requested by user.
		fmt.Fprintf(os.Stderr, "NLB file support not fully implemented in CLI yet\n")
		os.Exit(1)
	} else {
		fmt.Fprintf(os.Stderr, "Assuming ALB log file\n")
		entries, err := parser.ParseLogFile(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing ALB file: %v\n", err)
			os.Exit(1)
		}
		for _, e := range entries {
			adapters = append(adapters, albAdapter{e})
		}
	}

	fmt.Fprintf(os.Stderr, "Parsed %d log entries\n", len(adapters))
	fmt.Fprintf(os.Stderr, "Converting to OTLP format...\n\n")

	// Group by resource
	grouped := make(map[string]*resourceGroup)

	for _, entry := range adapters {
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

	// Build OTLP payload
	payload := converter.OTLPPayload{
		ResourceLogs: []converter.ResourceLog{},
	}

	for _, group := range grouped {
		payload.ResourceLogs = append(payload.ResourceLogs, converter.ResourceLog{
			Resource: converter.ResourceAttributes{
				Attributes: group.ResourceAttrs,
			},
			ScopeLogs: []converter.ScopeLog{
				{
					Scope: converter.Scope{
						Name:    "lb-log-parser",
						Version: "1.0.0",
					},
					LogRecords: group.LogRecords,
				},
			},
		})
	}

	// Output as JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(payload); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

type resourceGroup struct {
	ResourceAttrs []converter.OTelAttribute
	LogRecords    []converter.OTelLogRecord
}

// Simple adapters for CLI
type albAdapter struct {
	*parser.ALBLogEntry
}

func (a albAdapter) GetResourceKey() string {
	arn := a.TargetGroupARN
	if arn == "" || arn == "-" {
		arn = a.ChosenCertARN
	}
	return arn
}

func (a albAdapter) GetResourceAttributes() []converter.OTelAttribute {
	return converter.ExtractResourceAttributes(a.ALBLogEntry)
}

func (a albAdapter) ToOTel() converter.OTelLogRecord {
	return converter.ConvertToOTel(a.ALBLogEntry)
}

type wapAdapter struct {
	*parser.WAFLogEntry
}

func (a wapAdapter) GetResourceKey() string {
	return a.WebACLID
}

func (a wapAdapter) GetResourceAttributes() []converter.OTelAttribute {
	// Reusing logic from main.go/WAFAdapter ideally, but duplicating for CLI simplicity
	// or create a shared package. I already created cmd/lambda/adapter but didn't put impl there.
	// I'll define minimal attributes here.
	attrs := []converter.OTelAttribute{
		{Key: "cloud.provider", Value: converter.OTelAnyValue{StringValue: stringPtr("aws")}},
		{Key: "cloud.platform", Value: converter.OTelAnyValue{StringValue: stringPtr("aws_waf")}},
		{Key: "cloud.service", Value: converter.OTelAnyValue{StringValue: stringPtr("waf")}},
		{Key: "aws.waf.web_acl_id", Value: converter.OTelAnyValue{StringValue: &a.WebACLID}},
	}
	return attrs
}

func (a wapAdapter) ToOTel() converter.OTelLogRecord {
	return converter.ConvertWAFToOTel(a.WAFLogEntry)
}

func stringPtr(s string) *string {
	return &s
}

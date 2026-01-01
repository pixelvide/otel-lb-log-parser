package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pixelvide/otel-lb-log-parser/pkg/parser"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <log-file-path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s /path/to/alb.log.gz\n", os.Args[0])
		os.Exit(1)
	}

	filePath := os.Args[1]

	var entries interface{}
	var count int
	var err error

	if strings.Contains(strings.ToLower(filePath), "waflogs") {
		fmt.Fprintf(os.Stderr, "Detected WAF log file\n")
		var wafEntries []*parser.WAFLogEntry
		wafEntries, err = parser.ParseWAFLogFile(filePath)
		entries = wafEntries
		count = len(wafEntries)
	} else {
		fmt.Fprintf(os.Stderr, "Assuming ALB log file\n")
		var albEntries []*parser.ALBLogEntry
		albEntries, err = parser.ParseLogFile(filePath)
		entries = albEntries
		count = len(albEntries)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing file: %v\n", err)
		os.Exit(1)
	}

	// Print results
	fmt.Fprintf(os.Stderr, "Parsed %d log entries from %s\n\n", count, filePath)

	// Output entries as JSON
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(entries); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}

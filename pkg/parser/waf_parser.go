package parser

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// WAFLogEntry represents a parsed AWS WAF log entry
type WAFLogEntry struct {
	Timestamp                   int64                `json:"timestamp"`
	FormatVersion               int                  `json:"formatVersion"`
	WebACLID                    string               `json:"webaclId"`
	TerminatingRuleID           string               `json:"terminatingRuleId"`
	TerminatingRuleType         string               `json:"terminatingRuleType"`
	Action                      string               `json:"action"`
	TerminatingRuleMatchDetails []MatchDetail        `json:"terminatingRuleMatchDetails"`
	HTTPSourceName              string               `json:"httpSourceName"`
	HTTPSourceID                string               `json:"httpSourceId"`
	RuleGroupList               []RuleGroup          `json:"ruleGroupList"`
	RateBasedRuleList           []RateBasedRule      `json:"rateBasedRuleList"`
	NonTerminatingMatchingRules []NonTerminatingRule `json:"nonTerminatingMatchingRules"`
	RequestHeadersInserted      []Header             `json:"requestHeadersInserted"`
	ResponseCodeSent            *int                 `json:"responseCodeSent"`
	HTTPRequest                 HTTPRequest          `json:"httpRequest"`
	Labels                      []Label              `json:"labels"`
}

type MatchDetail struct {
	ConditionType string   `json:"conditionType"`
	Location      string   `json:"location"`
	MatchedData   []string `json:"matchedData"`
}

type RuleGroup struct {
	RuleGroupID         string          `json:"ruleGroupId"`
	TerminatingRule     *RuleGroupRule  `json:"terminatingRule"`
	NonTerminatingRules []RuleGroupRule `json:"nonTerminatingRules"`
	ExcludedRules       []ExcludeRule   `json:"excludedRules"`
}

type RuleGroupRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
}

type ExcludeRule struct {
	ExclusionType string `json:"exclusionType"`
	RuleID        string `json:"ruleId"`
}

type RateBasedRule struct {
	RateBasedRuleID     string `json:"rateBasedRuleId"`
	RateBasedRuleName   string `json:"rateBasedRuleName"`
	LimitKey            string `json:"limitKey"`
	MaxRateAllowed      int    `json:"maxRateAllowed"`
	EvaluationWindowSec string `json:"evaluationWindowSec"` // Sometimes string in docs
}

type NonTerminatingRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
}

type HTTPRequest struct {
	ClientIP    string   `json:"clientIp"`
	Country     string   `json:"country"`
	Headers     []Header `json:"headers"`
	URI         string   `json:"uri"`
	Args        string   `json:"args"`
	HTTPVersion string   `json:"httpVersion"`
	HTTPMethod  string   `json:"httpMethod"`
	RequestID   string   `json:"requestId"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Label struct {
	Name string `json:"name"`
}

// ParseWAFLogFile parses a WAF log file (supports gzip, handles concatenated JSON)
func ParseWAFLogFile(filePath string) ([]*WAFLogEntry, error) {
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

	// WAF logs are often concatenated JSON objects, effectively JSON Lines but sometimes just concatenated
	// Using json.Decoder with More() handles this gracefully
	decoder := json.NewDecoder(reader)
	var entries []*WAFLogEntry

	for decoder.More() {
		var entry WAFLogEntry
		if err := decoder.Decode(&entry); err != nil {
			// If we encounter an error, we might stop or try to recover.
			// For now, return error as it might indicate corrupt file
			// EOF is handled by decoder.More() returning false
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to decode JSON: %w", err)
		}
		entries = append(entries, &entry)
	}

	return entries, nil
}

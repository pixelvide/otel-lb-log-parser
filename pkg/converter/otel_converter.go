package converter

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pixelvide/go-alb-processor/pkg/parser"
)

// OTelLogRecord represents an OpenTelemetry log record
type OTelLogRecord struct {
	TimeUnixNano   string                 `json:"timeUnixNano"`
	SeverityNumber int                    `json:"severityNumber"`
	SeverityText   string                 `json:"severityText"`
	Body           map[string]string      `json:"body"`
	Attributes     []OTelAttribute        `json:"attributes"`
	TraceID        string                 `json:"traceId"`
	SpanID         string                 `json:"spanId"`
}

// OTelAttribute represents a key-value attribute
type OTelAttribute struct {
	Key   string        `json:"key"`
	Value OTelAnyValue `json:"value"`
}

// OTelAnyValue represents a typed value
type OTelAnyValue struct {
	StringValue *string  `json:"stringValue,omitempty"`
	IntValue    *string  `json:"intValue,omitempty"`
	DoubleValue *float64 `json:"doubleValue,omitempty"`
	BoolValue   *bool    `json:"boolValue,omitempty"`
}

// ResourceAttributes represents resource-level attributes
type ResourceAttributes struct {
	Attributes []OTelAttribute `json:"attributes"`
}

// ScopeLog represents a scope with log records
type ScopeLog struct {
	Scope      Scope            `json:"scope"`
	LogRecords []OTelLogRecord `json:"logRecords"`
}

// Scope represents instrumentation scope
type Scope struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ResourceLog represents a resource with scope logs
type ResourceLog struct {
	Resource  ResourceAttributes `json:"resource"`
	ScopeLogs []ScopeLog        `json:"scopeLogs"`
}

// OTLPPayload represents the complete OTLP payload
type OTLPPayload struct {
	ResourceLogs []ResourceLog `json:"resourceLogs"`
}

// ParseTraceID extracts W3C trace ID from ALB trace ID
// ALB format: Root=1-58337262-36d228ad5d99923122bbe354
// W3C format: 5833726236d228ad5d99923122bbe354 (32 hex chars)
func ParseTraceID(albTraceID string) string {
	if albTraceID == "" || albTraceID == "-" {
		return ""
	}

	// Remove "Root=" prefix
	albTraceID = strings.TrimPrefix(albTraceID, "Root=")
	
	// Split by hyphens: ['1', '58337262', '36d228ad5d99923122bbe354']
	parts := strings.Split(albTraceID, "-")
	
	if len(parts) >= 3 {
		// Combine timestamp (8 chars) + unique ID (24 chars) = 32 chars
		traceID := parts[1] + parts[2]
		
		// Validate it's 32 hex characters
		if len(traceID) == 32 && isHex(traceID) {
			return strings.ToLower(traceID)
		}
	}
	
	return ""
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ParseRequestURL extracts HTTP attributes from URL
func ParseRequestURL(requestURL string) map[string]string {
	attrs := make(map[string]string)
	
	if requestURL == "" || requestURL == "-" {
		return attrs
	}
	
	u, err := url.Parse(requestURL)
	if err != nil {
		return attrs
	}
	
	if u.Scheme != "" {
		attrs["http.scheme"] = u.Scheme
	}
	
	if u.Path != "" {
		attrs["url.path"] = u.Path
		
		if u.RawQuery != "" {
			attrs["url.query"] = u.RawQuery
			attrs["http.target"] = u.Path + "?" + u.RawQuery
		} else {
			attrs["http.target"] = u.Path
		}
	}
	
	return attrs
}

// ExtractResourceAttributes extracts cloud resource attributes from ALB entry
func ExtractResourceAttributes(entry *parser.ALBLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{
		{Key: "cloud.provider", Value: stringValue("aws")},
		{Key: "cloud.platform", Value: stringValue("aws_elastic_load_balancing")},
		{Key: "service.name", Value: stringValue("alb-log-parser")},
	}
	
	// Extract region and account from ARN
	arn := entry.TargetGroupARN
	if arn == "" || arn == "-" {
		arn = entry.ChosenCertARN
	}
	
	if arn != "" && arn != "-" {
		parts := strings.Split(arn, ":")
		if len(parts) >= 5 {
			attrs = append(attrs,
				OTelAttribute{Key: "cloud.region", Value: stringValue(parts[3])},
				OTelAttribute{Key: "cloud.account.id", Value: stringValue(parts[4])},
			)
		}
	}
	
	return attrs
}

// ConvertToOTel converts ALB log entry to OTLP log record
func ConvertToOTel(entry *parser.ALBLogEntry) OTelLogRecord {
	// Convert timestamp
	timeUnixNano := convertTimestamp(entry.Time)
	
	// Build attributes
	attributes := buildAttributes(entry)
	
	// Determine severity
	severityText := "INFO"
	severityNumber := 9
	
	if entry.ELBStatusCode >= 500 {
		severityText = "ERROR"
		severityNumber = 17
	} else if entry.ELBStatusCode >= 400 {
		severityText = "WARN"
		severityNumber = 13
	}
	
	// Build body
	bodyContent := fmt.Sprintf("%s %s %s", entry.RequestVerb, entry.RequestURL, entry.RequestProto)
	
	// Parse trace ID
	traceID := ParseTraceID(entry.TraceID)
	
	return OTelLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timeUnixNano),
		SeverityNumber: severityNumber,
		SeverityText:   severityText,
		Body:           map[string]string{"stringValue": bodyContent},
		Attributes:     attributes,
		TraceID:        traceID,
		SpanID:         "",
	}
}

func buildAttributes(entry *parser.ALBLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{}
	
	// HTTP attributes
	addAttr(&attrs, "http.request.method", entry.RequestVerb)
	addIntAttr(&attrs, "http.response.status_code", entry.ELBStatusCode)
	addInt64Attr(&attrs, "http.request.body.size", entry.ReceivedBytes)
	addInt64Attr(&attrs, "http.response.body.size", entry.SentBytes)
	addAttr(&attrs, "url.full", entry.RequestURL)
	
	// Parse URL for additional attributes
	urlAttrs := ParseRequestURL(entry.RequestURL)
	for k, v := range urlAttrs {
		addAttr(&attrs, k, v)
	}
	
	// Network attributes
	addAttr(&attrs, "network.protocol.name", "http")
	addAttr(&attrs, "network.protocol.version", entry.RequestProto)
	
	// Client attributes
	addAttr(&attrs, "client.address", entry.ClientIP)
	addIntAttr(&attrs, "client.port", entry.ClientPort)
	
	// Server attributes
	addAttr(&attrs, "server.address", entry.DomainName)
	addAttr(&attrs, "server.socket.address", entry.TargetIP)
	addIntAttr(&attrs, "server.socket.port", entry.TargetPort)
	
	// User agent
	addAttr(&attrs, "user_agent.original", entry.UserAgent)
	
	// TLS attributes
	addAttr(&attrs, "tls.cipher_suite", entry.SSLCipher)
	addAttr(&attrs, "tls.protocol.version", entry.SSLProtocol)
	
	// AWS-specific attributes
	addAttr(&attrs, "aws.alb.type", entry.Type)
	addAttr(&attrs, "aws.lb.name", entry.ELB)
	addFloatAttr(&attrs, "aws.alb.request_processing_time", entry.RequestProcessingTime)
	addFloatAttr(&attrs, "aws.alb.target_processing_time", entry.TargetProcessingTime)
	addFloatAttr(&attrs, "aws.alb.response_processing_time", entry.ResponseProcessingTime)
	addAttr(&attrs, "aws.alb.target_status_code", entry.TargetStatusCode)
	addAttr(&attrs, "aws.alb.target_group_arn", entry.TargetGroupARN)
	addAttr(&attrs, "aws.alb.trace_id", entry.TraceID)
	addAttr(&attrs, "aws.alb.chosen_cert_arn", entry.ChosenCertARN)
	addAttr(&attrs, "aws.alb.matched_rule_priority", entry.MatchedRulePriority)
	addAttr(&attrs, "aws.alb.request_creation_time", entry.RequestCreationTime)
	addAttr(&attrs, "aws.alb.actions_executed", entry.ActionsExecuted)
	addAttr(&attrs, "aws.alb.redirect_url", entry.RedirectURL)
	addAttr(&attrs, "aws.alb.lambda_error_reason", entry.LambdaErrorReason)
	addAttr(&attrs, "aws.alb.target_port_list", entry.TargetPortList)
	addAttr(&attrs, "aws.alb.target_status_code_list", entry.TargetStatusCodeList)
	addAttr(&attrs, "aws.alb.classification", entry.Classification)
	addAttr(&attrs, "aws.alb.classification_reason", entry.ClassificationReason)
	addAttr(&attrs, "aws.alb.conn_trace_id", entry.ConnTraceID)
	
	return attrs
}

// Helper functions
func convertTimestamp(timeStr string) int64 {
	if timeStr == "" {
		return time.Now().UnixNano()
	}
	
	t, err := time.Parse("2006-01-02T15:04:05.999999Z", timeStr)
	if err != nil {
		return time.Now().UnixNano()
	}
	
	return t.UnixNano()
}

func stringValue(s string) OTelAnyValue {
	return OTelAnyValue{StringValue: &s}
}

func intValue(i int) OTelAnyValue {
	s := fmt.Sprintf("%d", i)
	return OTelAnyValue{IntValue: &s}
}

func floatValue(f float64) OTelAnyValue {
	return OTelAnyValue{DoubleValue: &f}
}

func addAttr(attrs *[]OTelAttribute, key, value string) {
	if value != "" && value != "-" {
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: stringValue(value),
		})
	}
}

func addIntAttr(attrs *[]OTelAttribute, key string, value int) {
	if value != 0 {
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: intValue(value),
		})
	}
}

func addInt64Attr(attrs *[]OTelAttribute, key string, value int64) {
	if value != 0 {
		s := fmt.Sprintf("%d", value)
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: OTelAnyValue{IntValue: &s},
		})
	}
}

func addFloatAttr(attrs *[]OTelAttribute, key string, value float64) {
	if value != 0 {
		*attrs = append(*attrs, OTelAttribute{
			Key:   key,
			Value: floatValue(value),
		})
	}
}

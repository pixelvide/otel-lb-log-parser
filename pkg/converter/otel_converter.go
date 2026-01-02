package converter

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pixelvide/otel-aws-log-parser/pkg/parser"
)

// OTelLogRecord represents an OpenTelemetry log record
type OTelLogRecord struct {
	TimeUnixNano   string            `json:"timeUnixNano"`
	SeverityNumber int               `json:"severityNumber"`
	SeverityText   string            `json:"severityText"`
	Body           map[string]string `json:"body"`
	Attributes     []OTelAttribute   `json:"attributes"`
	TraceID        string            `json:"traceId"`
	SpanID         string            `json:"spanId"`
}

// OTelAttribute represents a key-value attribute
type OTelAttribute struct {
	Key   string       `json:"key"`
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
	Scope      Scope           `json:"scope"`
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
	ScopeLogs []ScopeLog         `json:"scopeLogs"`
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
		{Key: "cloud.service", Value: stringValue("elasticloadbalancing")},
		{Key: "service.name", Value: stringValue("alb-log-parser")},
		{Key: "aws.lb.name", Value: stringValue(entry.ELB)},
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

	// Generate a random Span ID (16 hex chars)
	// This makes the log entry appear as a span in the trace
	spanID := generateSpanID()

	return OTelLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timeUnixNano),
		SeverityNumber: severityNumber,
		SeverityText:   severityText,
		Body:           map[string]string{"stringValue": bodyContent},
		Attributes:     attributes,
		TraceID:        traceID,
		SpanID:         spanID,
	}
}

// generateSpanID generates a random 8-byte hex string (16 chars)
func generateSpanID() string {
	b := make([]byte, 8)
	// Use time as seed for simple randomness, or crypto/rand for better
	// For high-throughput logs, math/rand seeded once is faster,
	// but here we'll just use a simple hex generation from random bytes
	// Note: In a real high-perf scenario, use a proper random source
	// For now, using a simple pseudo-random approach based on time is sufficient
	// or just reading from crypto/rand

	// Using a simple fast approach:
	// We need 16 hex chars.
	// Let's use crypto/rand properly
	_, err := rand.Read(b)
	if err != nil {
		// Fallback if rand fails (unlikely)
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
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

// ConvertNLBToOTel converts NLB log entry to OTLP log record
func ConvertNLBToOTel(entry *parser.NLBLogEntry) OTelLogRecord {
	// Convert timestamp
	timeUnixNano := convertTimestamp(entry.Time)

	// Build attributes
	attributes := buildAttributesNLB(entry)

	// Determine severity (NLB doesn't have HTTP status codes usually, maybe check for errors?)
	// Default to INFO
	severityText := "INFO"
	severityNumber := 9

	// Build body
	bodyContent := fmt.Sprintf("%s log for %s", entry.Type, entry.ELB)

	// Generate trace and span IDs
	// NLB doesn't have X-Amzn-Trace-Id in valid log fields usually, but sometimes has TraceID?
	// Our struct doesn't have TraceID, but TLS logs might.
	// For now, generate random TraceID/SpanID
	traceID := generateTraceID()
	spanID := generateSpanID()

	return OTelLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timeUnixNano),
		SeverityNumber: severityNumber,
		SeverityText:   severityText,
		Body:           map[string]string{"stringValue": bodyContent},
		Attributes:     attributes,
		TraceID:        traceID,
		SpanID:         spanID,
	}
}

func buildAttributesNLB(entry *parser.NLBLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{}

	// Transport attributes
	addAttr(&attrs, "network.transport", "tcp") // Mostly TCP for NLB
	addAttr(&attrs, "network.protocol.name", entry.Type)
	addAttr(&attrs, "network.protocol.version", entry.Version)

	// Client attributes
	addAttr(&attrs, "client.address", entry.ClientIP)
	addIntAttr(&attrs, "client.port", entry.ClientPort)

	// Server attributes
	addAttr(&attrs, "server.address", entry.TargetIP)
	addIntAttr(&attrs, "server.port", entry.TargetPort)

	// TLS attributes
	addAttr(&attrs, "tls.cipher_suite", entry.TLSCipher)
	addAttr(&attrs, "tls.protocol.version", entry.TLSProtocolVersion)
	addAttr(&attrs, "tls.server.name", entry.DomainName)

	// AWS-specific attributes
	addAttr(&attrs, "aws.nlb.type", entry.Type)
	addAttr(&attrs, "aws.nlb.listener_id", entry.ListenerID)
	addFloatAttr(&attrs, "aws.nlb.connection_time", entry.ConnectionTime)
	addFloatAttr(&attrs, "aws.nlb.tls_handshake_time", entry.TLSHandshakeTime)
	addInt64Attr(&attrs, "aws.nlb.received_bytes", entry.ReceivedBytes)
	addInt64Attr(&attrs, "aws.nlb.sent_bytes", entry.SentBytes)
	addAttr(&attrs, "aws.nlb.incoming_tls_alert", entry.IncomingTLSAlert)
	addAttr(&attrs, "aws.nlb.chosen_cert_arn", entry.ChosenCertARN)
	addAttr(&attrs, "aws.nlb.chosen_cert_serial", entry.ChosenCertSerial)
	addAttr(&attrs, "aws.nlb.tls_named_group", entry.TLSNamedGroup)
	addAttr(&attrs, "aws.nlb.alpn_frontend_protocol", entry.ALPNFrontEndProtocol)
	addAttr(&attrs, "aws.nlb.alpn_backend_protocol", entry.ALPNBackEndProtocol)
	addAttr(&attrs, "aws.nlb.alpn_client_preference_list", entry.ALPNClientPreferenceList)
	addAttr(&attrs, "aws.nlb.tls_connection_creation_time", entry.TLSConnectionCreationTime)

	return attrs
}

// ExtractResourceAttributesNLB extracts cloud resource attributes from NLB entry
func ExtractResourceAttributesNLB(entry *parser.NLBLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{
		{Key: "cloud.provider", Value: stringValue("aws")},
		{Key: "cloud.platform", Value: stringValue("aws_elastic_load_balancing")},
		{Key: "cloud.service", Value: stringValue("elasticloadbalancing")},
		{Key: "service.name", Value: stringValue("nlb-log-parser")},
		{Key: "aws.lb.name", Value: stringValue(entry.ELB)},
	}

	// Extract region and account from ARN (ListenerID usually contains full ARN)
	// Example: listener/net/my-load-balancer/5d4...
	// Or ChosenCertARN

	arn := entry.ChosenCertARN

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

// generateTraceID generates a random 16-byte hex string (32 chars)
func generateTraceID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// ConvertWAFToOTel converts WAF log entry to OTLP log record
func ConvertWAFToOTel(entry *parser.WAFLogEntry) OTelLogRecord {
	// WAF timestamp is already int64 (milliseconds)
	timeUnixNano := entry.Timestamp * 1000000

	attributes := buildAttributesWAF(entry)

	severityText := "INFO"
	severityNumber := 9
	if entry.Action == "BLOCK" {
		severityText = "WARN"
		severityNumber = 13
	}

	bodyContent := fmt.Sprintf("%s %s %s", entry.HTTPRequest.HTTPMethod, entry.HTTPRequest.URI, entry.Action)

	traceID := ""
	// Try to extract Trace ID from headers
	for _, h := range entry.HTTPRequest.Headers {
		if strings.EqualFold(h.Name, "X-Amzn-Trace-Id") {
			traceID = ParseTraceID(h.Value)
			break
		}
	}

	// Fallback to RequestID if it matches Trace ID format
	if traceID == "" && entry.HTTPRequest.RequestID != "" {
		traceID = ParseTraceID(entry.HTTPRequest.RequestID)
	}

	if traceID == "" {
		traceID = generateTraceID()
	}

	spanID := generateSpanID()

	return OTelLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timeUnixNano),
		SeverityNumber: severityNumber,
		SeverityText:   severityText,
		Body:           map[string]string{"stringValue": bodyContent},
		Attributes:     attributes,
		TraceID:        traceID,
		SpanID:         spanID,
	}
}

func buildAttributesWAF(entry *parser.WAFLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{}

	// WAF Attributes
	addAttr(&attrs, "aws.waf.web_acl_id", entry.WebACLID)
	addAttr(&attrs, "aws.waf.terminating_rule_id", entry.TerminatingRuleID)
	addAttr(&attrs, "aws.waf.terminating_rule_type", entry.TerminatingRuleType)
	addAttr(&attrs, "aws.waf.action", entry.Action)
	addAttr(&attrs, "aws.waf.http_source_name", entry.HTTPSourceName)
	addAttr(&attrs, "aws.waf.http_source_id", entry.HTTPSourceID)

	// HTTP Attributes
	req := entry.HTTPRequest
	addAttr(&attrs, "http.request.method", req.HTTPMethod)
	addAttr(&attrs, "url.path", req.URI)
	addAttr(&attrs, "url.query", req.Args)
	addAttr(&attrs, "network.protocol.version", req.HTTPVersion)
	addAttr(&attrs, "client.address", req.ClientIP)

	// User Agent from headers
	for _, h := range req.Headers {
		if strings.EqualFold(h.Name, "User-Agent") {
			addAttr(&attrs, "user_agent.original", h.Value)
		}
		if strings.EqualFold(h.Name, "Host") {
			addAttr(&attrs, "server.address", h.Value)
		}
	}

	// Additional Details
	addAttr(&attrs, "client.geo.country_iso_code", req.Country)
	addInt64Attr(&attrs, "http.request.body.size", entry.RequestBodySize)
	addInt64Attr(&attrs, "aws.waf.request_body_size_inspected", entry.RequestBodySizeInspected)
	addAttr(&attrs, "tls.client.ja3", entry.JA3Fingerprint)
	addAttr(&attrs, "tls.client.ja4", entry.JA4Fingerprint)

	if len(entry.Labels) > 0 {
		var labels []string
		for _, l := range entry.Labels {
			labels = append(labels, l.Name)
		}
		// JSON encode string array for easier querying in some backends,
		// otherwise we could use array value if OTel library fully supported it easily here.
		// For simplicity/compatibility, joining with comma or JSON string is often used.
		// Using JSON for robust array representation.
		lblBytes, _ := json.Marshal(labels)
		addAttr(&attrs, "aws.waf.labels", string(lblBytes))
	}

	// Collect all processed rules
	processedRules := collectProcessedRules(entry)
	if len(processedRules) > 0 {
		jsonBytes, err := json.Marshal(processedRules)
		if err == nil {
			addAttr(&attrs, "aws.waf.processed_rules", string(jsonBytes))
		}
	}

	return attrs
}

type ProcessedRule struct {
	RuleID string `json:"ruleId"`
	Action string `json:"action"`
	Type   string `json:"type,omitempty"` // TERMINATING, NON_TERMINATING, GROUP
}

func collectProcessedRules(entry *parser.WAFLogEntry) []ProcessedRule {
	var rules []ProcessedRule

	// 1. Terminating Rule
	if entry.TerminatingRuleID != "" {
		rules = append(rules, ProcessedRule{
			RuleID: entry.TerminatingRuleID,
			Action: entry.Action,
			Type:   "TERMINATING",
		})
	}

	// 2. Non-Terminating Rules
	for _, rule := range entry.NonTerminatingMatchingRules {
		rules = append(rules, ProcessedRule{
			RuleID: rule.RuleID,
			Action: rule.Action,
			Type:   "NON_TERMINATING",
		})
	}

	// 3. Rule Groups
	for _, group := range entry.RuleGroupList {
		// If the group itself has specific actions or inner rules
		if group.TerminatingRule != nil {
			rules = append(rules, ProcessedRule{
				RuleID: group.TerminatingRule.RuleID,
				Action: group.TerminatingRule.Action,
				Type:   "GROUP_TERMINATING",
			})
		}
		for _, rule := range group.NonTerminatingRules {
			rules = append(rules, ProcessedRule{
				RuleID: rule.RuleID,
				Action: rule.Action,
				Type:   "GROUP_NON_TERMINATING",
			})
		}
	}

	return rules
}

// ConvertCloudFrontToOTel converts CloudFront log entry to OTLP log record
func ConvertCloudFrontToOTel(entry *parser.CloudFrontLogEntry) OTelLogRecord {
	// Convert timestamp
	// Date: 2019-12-04, Time: 21:02:31
	timeStr := fmt.Sprintf("%sT%sZ", entry.Date, entry.Time)
	t, err := time.Parse(time.RFC3339, timeStr)
	var timeUnixNano int64
	if err != nil {
		timeUnixNano = time.Now().UnixNano()
	} else {
		timeUnixNano = t.UnixNano()
	}

	attributes := buildAttributesCloudFront(entry)

	severityText := "INFO"
	severityNumber := 9
	if entry.SCStatus >= 500 {
		severityText = "ERROR"
		severityNumber = 17
	} else if entry.SCStatus >= 400 {
		severityText = "WARN"
		severityNumber = 13
	}

	bodyContent := fmt.Sprintf("%s %s %d", entry.CSMethod, entry.CSURIStem, entry.SCStatus)

	traceID := ""
	// Use x-edge-request-id as trace ID if it fits format, but it's base64 usually.
	// CloudFront Request IDs are long base64 strings, not valid W3C Trace IDs.
	// So we generate a random Trace ID.
	traceID = generateTraceID()
	spanID := generateSpanID()

	return OTelLogRecord{
		TimeUnixNano:   fmt.Sprintf("%d", timeUnixNano),
		SeverityNumber: severityNumber,
		SeverityText:   severityText,
		Body:           map[string]string{"stringValue": bodyContent},
		Attributes:     attributes,
		TraceID:        traceID,
		SpanID:         spanID,
	}
}

func buildAttributesCloudFront(entry *parser.CloudFrontLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{}

	// HTTP Attributes
	addAttr(&attrs, "http.request.method", entry.CSMethod)
	addIntAttr(&attrs, "http.response.status_code", entry.SCStatus)
	addAttr(&attrs, "url.path", entry.CSURIStem)
	addAttr(&attrs, "url.query", entry.CSURIQuery)
	addAttr(&attrs, "network.protocol.version", entry.CSProtocolVersion) // e.g. HTTP/2.0
	addAttr(&attrs, "network.protocol.name", entry.CSProtocol)           // http/https

	// User Agent
	decodedUA, err := url.QueryUnescape(entry.CSUserAgent)
	if err == nil {
		addAttr(&attrs, "user_agent.original", decodedUA)
	} else {
		addAttr(&attrs, "user_agent.original", entry.CSUserAgent)
	}

	// Client
	addAttr(&attrs, "client.address", entry.CIP)
	addIntAttr(&attrs, "client.port", entry.CPort)

	// Server
	addAttr(&attrs, "server.address", entry.CSHost) // Distribution domain or CNAME

	// AWS CloudFront Specific
	addAttr(&attrs, "aws.cloudfront.edge_location", entry.XEdgeLocation)
	addInt64Attr(&attrs, "aws.cloudfront.sc_bytes", entry.SCBytes)
	addInt64Attr(&attrs, "aws.cloudfront.cs_bytes", entry.CSBytes)
	addAttr(&attrs, "aws.cloudfront.result_type", entry.XEdgeResultType)
	addAttr(&attrs, "aws.cloudfront.request_id", entry.XEdgeRequestID)
	addAttr(&attrs, "aws.cloudfront.host_header", entry.XHostHeader)
	addFloatAttr(&attrs, "aws.cloudfront.time_taken", entry.TimeTaken)
	addAttr(&attrs, "aws.cloudfront.x_forwarded_for", entry.XForwardedFor)
	addAttr(&attrs, "aws.cloudfront.ssl_protocol", entry.SSLProtocol)
	addAttr(&attrs, "aws.cloudfront.ssl_cipher", entry.SSLCipher)
	addAttr(&attrs, "aws.cloudfront.response_result_type", entry.XEdgeResponseResultType)
	addAttr(&attrs, "aws.cloudfront.fle_status", entry.FLEStatus)
	addIntAttr(&attrs, "aws.cloudfront.fle_encrypted_fields", entry.FLEEncryptedFields)
	addFloatAttr(&attrs, "aws.cloudfront.time_to_first_byte", entry.TimeToFirstByte)
	addAttr(&attrs, "aws.cloudfront.detailed_result_type", entry.XEdgeDetailedResultType)
	addAttr(&attrs, "aws.cloudfront.sc_content_type", entry.SCContentType)
	addInt64Attr(&attrs, "aws.cloudfront.sc_content_len", entry.SCContentLen)
	addAttr(&attrs, "aws.cloudfront.sc_range_start", entry.SCRangeStart)
	addAttr(&attrs, "aws.cloudfront.sc_range_end", entry.SCRangeEnd)

	// Cookie (often contains sensitive info, maybe mask or exclude? AWS logs it)
	// addAttr(&attrs, "aws.cloudfront.cookie", entry.CSCookie)

	return attrs
}

// ExtractResourceAttributesCloudFront extracts cloud resource attributes from CloudFront entry
func ExtractResourceAttributesCloudFront(entry *parser.CloudFrontLogEntry) []OTelAttribute {
	attrs := []OTelAttribute{
		{Key: "cloud.provider", Value: stringValue("aws")},
		{Key: "cloud.platform", Value: stringValue("aws_cloudfront")},
		{Key: "cloud.service", Value: stringValue("cloudfront")},
		{Key: "service.name", Value: stringValue("cloudfront-log-parser")},
	}

	// Distribution ID is usually part of the filename, not the log entry itself (except cs(Host) is domain)
	// cs(Host) example: d111111abcdef8.cloudfront.net
	if entry.CSHost != "" && strings.HasSuffix(entry.CSHost, ".cloudfront.net") {
		distID := strings.TrimSuffix(entry.CSHost, ".cloudfront.net")
		attrs = append(attrs, OTelAttribute{Key: "aws.cloudfront.distribution_id", Value: stringValue(distID)})
	}

	return attrs
}

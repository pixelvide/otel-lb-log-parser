package adapter

import (
	"github.com/pixelvide/otel-lb-log-parser/pkg/converter"
)

// LogAdapter interface for polymorphic log handling
type LogAdapter interface {
	GetResourceKey() string
	GetResourceAttributes() []converter.OTelAttribute
	ToOTel() converter.OTelLogRecord
}

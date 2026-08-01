package config

import (
	"strings"
)

// Problem is one actionable configuration validation failure.
type Problem struct {
	Variable string
	Reason   string
}

// ValidationError aggregates all discoverable configuration failures.
type ValidationError struct {
	Problems []Problem
}

func (e *ValidationError) Error() string {
	if e == nil || len(e.Problems) == 0 {
		return "invalid configuration"
	}
	var builder strings.Builder
	builder.WriteString("invalid configuration:")
	for _, problem := range e.Problems {
		builder.WriteString("\n - ")
		builder.WriteString(problem.Variable)
		builder.WriteString(": ")
		builder.WriteString(problem.Reason)
	}
	return builder.String()
}

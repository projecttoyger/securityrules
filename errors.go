package securityrules

import "fmt"

// Common error codes for better error handling
const (
	ErrCodeInvalidRule      = "INVALID_RULE"
	ErrCodeInvalidContext   = "INVALID_CONTEXT"
	ErrCodeInvalidCondition = "INVALID_CONDITION"
	ErrCodeEvaluation       = "EVALUATION_ERROR"
)

// SecurityError represents a base error interface for the security package
type SecurityError interface {
	error
	Code() string
}

// ErrInvalidRule represents a rule validation error
type ErrInvalidRule struct {
	ErrorCode string
	Message   string
}

func (e ErrInvalidRule) Error() string {
	return fmt.Sprintf("invalid rule: %s", e.Message)
}

func (e ErrInvalidRule) Code() string {
	if e.ErrorCode == "" {
		return ErrCodeInvalidRule
	}
	return e.ErrorCode
}

// NewInvalidRuleError creates a new ErrInvalidRule with a message
func NewInvalidRuleError(message string) ErrInvalidRule {
	return ErrInvalidRule{
		ErrorCode: ErrCodeInvalidRule,
		Message:   message,
	}
}

// ErrInvalidContext indicates that the evaluation context is invalid
type ErrInvalidContext struct {
	ErrorCode string
	Message   string
}

func (e ErrInvalidContext) Error() string {
	return fmt.Sprintf("invalid context: %s", e.Message)
}

func (e ErrInvalidContext) Code() string {
	if e.ErrorCode == "" {
		return ErrCodeInvalidContext
	}
	return e.ErrorCode
}

// NewInvalidContextError creates a new ErrInvalidContext with a message
func NewInvalidContextError(message string) ErrInvalidContext {
	return ErrInvalidContext{
		ErrorCode: ErrCodeInvalidContext,
		Message:   message,
	}
}

// ErrInvalidCondition represents a condition validation error
type ErrInvalidCondition struct {
	ErrorCode string
	Message   string
	Field     string
}

func (e ErrInvalidCondition) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("invalid condition in field '%s': %s", e.Field, e.Message)
	}
	return fmt.Sprintf("invalid condition: %s", e.Message)
}

func (e ErrInvalidCondition) Code() string {
	if e.ErrorCode == "" {
		return ErrCodeInvalidCondition
	}
	return e.ErrorCode
}

// NewInvalidConditionError creates a new ErrInvalidCondition with a message
func NewInvalidConditionError(message string) ErrInvalidCondition {
	return ErrInvalidCondition{
		ErrorCode: ErrCodeInvalidCondition,
		Message:   message,
	}
}

// NewInvalidConditionFieldError creates a new ErrInvalidCondition with a field reference
func NewInvalidConditionFieldError(field, message string) ErrInvalidCondition {
	return ErrInvalidCondition{
		ErrorCode: ErrCodeInvalidCondition,
		Message:   message,
		Field:     field,
	}
}

// ErrEvaluation represents an error that occurred during rule evaluation
type ErrEvaluation struct {
	ErrorCode string
	Message   string
	RuleID    string
}

func (e ErrEvaluation) Error() string {
	if e.RuleID != "" {
		return fmt.Sprintf("evaluation error for rule '%s': %s", e.RuleID, e.Message)
	}
	return fmt.Sprintf("evaluation error: %s", e.Message)
}

func (e ErrEvaluation) Code() string {
	if e.ErrorCode == "" {
		return ErrCodeEvaluation
	}
	return e.ErrorCode
}

// NewEvaluationError creates a new ErrEvaluation with a message
func NewEvaluationError(message string) ErrEvaluation {
	return ErrEvaluation{
		ErrorCode: ErrCodeEvaluation,
		Message:   message,
	}
}

// NewRuleEvaluationError creates a new ErrEvaluation with a rule reference
func NewRuleEvaluationError(ruleID, message string) ErrEvaluation {
	return ErrEvaluation{
		ErrorCode: ErrCodeEvaluation,
		Message:   message,
		RuleID:    ruleID,
	}
}

// IsInvalidRuleError checks if an error is an ErrInvalidRule
func IsInvalidRuleError(err error) bool {
	_, ok := err.(ErrInvalidRule)
	return ok
}

// IsInvalidContextError checks if an error is an ErrInvalidContext
func IsInvalidContextError(err error) bool {
	_, ok := err.(ErrInvalidContext)
	return ok
}

// IsInvalidConditionError checks if an error is an ErrInvalidCondition
func IsInvalidConditionError(err error) bool {
	_, ok := err.(ErrInvalidCondition)
	return ok
}

// IsEvaluationError checks if an error is an ErrEvaluation
func IsEvaluationError(err error) bool {
	_, ok := err.(ErrEvaluation)
	return ok
}

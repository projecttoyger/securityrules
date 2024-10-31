package securityrules

import "fmt"

// ErrInvalidRule indicates that a rule is malformed
type ErrInvalidRule struct {
	Message string
}

func (e ErrInvalidRule) Error() string {
	return fmt.Sprintf("invalid rule: %s", e.Message)
}

// ErrInvalidContext indicates that the evaluation context is invalid
type ErrInvalidContext struct {
	Message string
}

func (e ErrInvalidContext) Error() string {
	return fmt.Sprintf("invalid context: %s", e.Message)
}

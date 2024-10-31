package securityrules

import (
	"testing"
)

func TestErrors(t *testing.T) {
	t.Run("ErrInvalidRule", func(t *testing.T) {
		err := ErrInvalidRule{Message: "test error"}
		expected := "invalid rule: test error"
		if err.Error() != expected {
			t.Errorf("Error() = %v, want %v", err.Error(), expected)
		}
	})

	t.Run("ErrInvalidContext", func(t *testing.T) {
		err := ErrInvalidContext{Message: "test error"}
		expected := "invalid context: test error"
		if err.Error() != expected {
			t.Errorf("Error() = %v, want %v", err.Error(), expected)
		}
	})
}

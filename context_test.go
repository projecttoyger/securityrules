package securityrules

import (
	"reflect"
	"testing"
)

func TestContext_Methods(t *testing.T) {
	t.Run("all context methods", func(t *testing.T) {
		// Test data
		userData := map[string]interface{}{"id": "user1"}
		resourceData := map[string]interface{}{"id": "res1"}
		envData := map[string]interface{}{"time": "now"}

		// Create context and set all fields
		ctx := NewContext().
			WithUser(userData).
			WithResource(resourceData).
			WithEnvironment(envData)

		// Test User()
		if !reflect.DeepEqual(ctx.User(), userData) {
			t.Errorf("User() = %v, want %v", ctx.User(), userData)
		}

		// Test Resource()
		if !reflect.DeepEqual(ctx.Resource(), resourceData) {
			t.Errorf("Resource() = %v, want %v", ctx.Resource(), resourceData)
		}

		// Test Environment()
		if !reflect.DeepEqual(ctx.Environment(), envData) {
			t.Errorf("Environment() = %v, want %v", ctx.Environment(), envData)
		}
	})

	t.Run("chaining methods", func(t *testing.T) {
		ctx := NewContext()

		// Test method chaining
		chainedCtx := ctx.
			WithUser(map[string]interface{}{"id": "1"}).
			WithResource(map[string]interface{}{"id": "2"}).
			WithEnvironment(map[string]interface{}{"id": "3"})

		if chainedCtx != ctx {
			t.Error("Method chaining should return same context instance")
		}
	})

	t.Run("nil values", func(t *testing.T) {
		ctx := NewContext()

		// Test setting nil values
		ctx.WithUser(nil)
		if ctx.User() != nil {
			t.Error("User should be nil")
		}

		ctx.WithResource(nil)
		if ctx.Resource() != nil {
			t.Error("Resource should be nil")
		}

		ctx.WithEnvironment(nil)
		if ctx.Environment() != nil {
			t.Error("Environment should be nil")
		}
	})
}

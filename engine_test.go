package securityrules

import (
	"testing"
)

func TestEngine_AddRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    *Rule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: NewRule().
				ForResource("documents").
				WithAction("read").
				WithEffect(Allow),
			wantErr: false,
		},
		{
			name: "missing resource",
			rule: NewRule().
				WithAction("read").
				WithEffect(Allow),
			wantErr: true,
		},
		{
			name: "missing action",
			rule: NewRule().
				ForResource("documents").
				WithEffect(Allow),
			wantErr: true,
		},
		{
			name: "invalid effect",
			rule: NewRule().
				ForResource("documents").
				WithAction("read").
				WithEffect("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			err := engine.AddRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngine_IsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Engine) error
		context  *Context
		resource string
		action   string
		want     bool
		wantErr  bool
	}{
		{
			name: "allowed for admin",
			setup: func(e *Engine) error {
				return e.AddRule(NewRule().
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow).
					WithCondition("userRole", "admin"))
			},
			context: NewContext().WithUser(map[string]interface{}{
				"roles": []string{"admin"},
			}),
			resource: "documents",
			action:   "read",
			want:     true,
			wantErr:  false,
		},
		{
			name: "denied for non-admin",
			setup: func(e *Engine) error {
				return e.AddRule(NewRule().
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow).
					WithCondition("userRole", "admin"))
			},
			context: NewContext().WithUser(map[string]interface{}{
				"roles": []string{"user"},
			}),
			resource: "documents",
			action:   "read",
			want:     false,
			wantErr:  false,
		},
		{
			name: "nil context",
			setup: func(e *Engine) error {
				return e.AddRule(NewRule().
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow))
			},
			context:  nil,
			resource: "documents",
			action:   "read",
			want:     false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			if tt.setup != nil {
				if err := tt.setup(engine); err != nil {
					t.Fatalf("Setup failed: %v", err)
				}
			}

			got, err := engine.IsAllowed(tt.resource, tt.action, tt.context)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEngine_DefaultDeny(t *testing.T) {
	engine := NewEngine()
	ctx := NewContext()

	// Test with no rules
	allowed, err := engine.IsAllowed("resource", "action", ctx)
	if err != nil {
		t.Errorf("IsAllowed() error = %v, want nil", err)
	}
	if allowed {
		t.Error("IsAllowed() should return false when no rules match")
	}
}

func TestEngine_EvaluationErrors(t *testing.T) {
	engine := NewEngine()

	// Add a rule with userRole condition but no roles in context
	rule := NewRule().
		ForResource("test").
		WithAction("action").
		WithEffect(Allow).
		WithCondition("userRole", "admin")

	err := engine.AddRule(rule)
	if err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	// Create context without roles
	ctx := NewContext().WithUser(map[string]interface{}{
		"id": "user1", // No roles field
	})

	allowed, err := engine.IsAllowed("test", "action", ctx)
	if err != nil {
		t.Errorf("IsAllowed() unexpected error: %v", err)
	}
	if allowed {
		t.Error("IsAllowed() should return false when role check fails")
	}
}

func TestEngine_ResourceOwner(t *testing.T) {
	tests := []struct {
		name     string
		context  *Context
		expected bool
	}{
		{
			name: "matching owner",
			context: NewContext().
				WithUser(map[string]interface{}{"id": "user1"}).
				WithResource(map[string]interface{}{"owner": "user1"}),
			expected: true,
		},
		{
			name: "non-matching owner",
			context: NewContext().
				WithUser(map[string]interface{}{"id": "user1"}).
				WithResource(map[string]interface{}{"owner": "user2"}),
			expected: false,
		},
		{
			name: "missing user id",
			context: NewContext().
				WithUser(map[string]interface{}{}).
				WithResource(map[string]interface{}{"owner": "user1"}),
			expected: false,
		},
		{
			name: "missing resource owner",
			context: NewContext().
				WithUser(map[string]interface{}{"id": "user1"}).
				WithResource(map[string]interface{}{}),
			expected: false,
		},
		{
			name: "nil user",
			context: NewContext().
				WithResource(map[string]interface{}{"owner": "user1"}),
			expected: false,
		},
		{
			name: "nil resource",
			context: NewContext().
				WithUser(map[string]interface{}{"id": "user1"}),
			expected: false,
		},
	}

	engine := NewEngine()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.matchResourceOwner(tt.context)
			if result != tt.expected {
				t.Errorf("matchResourceOwner() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestEngine_ResourceOwnerRule(t *testing.T) {
	engine := NewEngine()

	// Add rule with resource owner condition
	rule := NewRule().
		ForResource("documents").
		WithAction("read").
		WithEffect(Allow).
		WithCondition("resourceOwner", true)

	if err := engine.AddRule(rule); err != nil {
		t.Fatalf("Failed to add rule: %v", err)
	}

	tests := []struct {
		name     string
		context  *Context
		expected bool
	}{
		{
			name: "owner can access",
			context: NewContext().
				WithUser(map[string]interface{}{"id": "user1"}).
				WithResource(map[string]interface{}{"owner": "user1"}),
			expected: true,
		},
		{
			name: "non-owner cannot access",
			context: NewContext().
				WithUser(map[string]interface{}{"id": "user1"}).
				WithResource(map[string]interface{}{"owner": "user2"}),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed, err := engine.IsAllowed("documents", "read", tt.context)
			if err != nil {
				t.Errorf("IsAllowed() error = %v", err)
			}
			if allowed != tt.expected {
				t.Errorf("IsAllowed() = %v, want %v", allowed, tt.expected)
			}
		})
	}
}

package securityrules

import (
	"fmt"
	"testing"
)

func TestEngine_AddRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    *Rule
		wantErr bool
		errCode string
	}{
		{
			name: "valid rule",
			rule: NewRule().
				WithID("test-rule").
				ForResource("documents").
				WithAction("read").
				WithEffect(Allow),
			wantErr: false,
		},
		{
			name:    "nil rule",
			rule:    nil,
			wantErr: true,
			errCode: ErrCodeInvalidRule,
		},
		{
			name: "missing resource",
			rule: NewRule().
				WithAction("read").
				WithEffect(Allow),
			wantErr: true,
			errCode: ErrCodeInvalidRule,
		},
		{
			name: "missing action",
			rule: NewRule().
				ForResource("documents").
				WithEffect(Allow),
			wantErr: true,
			errCode: ErrCodeInvalidRule,
		},
		{
			name: "invalid effect",
			rule: NewRule().
				ForResource("documents").
				WithAction("read").
				WithEffect("invalid"),
			wantErr: true,
			errCode: ErrCodeInvalidRule,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			err := engine.AddRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.errCode != "" {
				if secErr, ok := err.(SecurityError); !ok {
					t.Errorf("Expected SecurityError, got %T", err)
				} else if secErr.Code() != tt.errCode {
					t.Errorf("Expected error code %s, got %s", tt.errCode, secErr.Code())
				}
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
		errCode  string
	}{
		{
			name: "allowed for admin with structured condition",
			setup: func(e *Engine) error {
				return e.AddRule(NewRule().
					WithID("admin-rule").
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow).
					WithStructuredCondition("userRole", Condition{
						Type:      RoleCondition,
						Operation: Equals,
						Value:     "admin",
						Message:   "Admin access required",
					}))
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
					WithID("admin-rule").
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow).
					WithStructuredCondition("userRole", Condition{
						Type:      RoleCondition,
						Operation: Equals,
						Value:     "admin",
					}))
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
			errCode:  ErrCodeInvalidContext,
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
			if err != nil && tt.errCode != "" {
				if secErr, ok := err.(SecurityError); !ok {
					t.Errorf("Expected SecurityError, got %T", err)
				} else if secErr.Code() != tt.errCode {
					t.Errorf("Expected error code %s, got %s", tt.errCode, secErr.Code())
				}
			}
			if got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func (e *timeConditionEvaluator) Evaluate(condition Condition, ctx *Context) (bool, error) {
	allowedTimes, ok := condition.Value.([]string)
	if !ok {
		return false, fmt.Errorf("invalid time format")
	}
	currentTime, ok := ctx.Environment()["time"].(string)
	if !ok {
		return false, fmt.Errorf("time not found in context")
	}
	for _, time := range allowedTimes {
		if time == currentTime {
			return true, nil
		}
	}
	return false, nil
}

// Custom time evaluator for testing
type timeConditionEvaluator struct{}

func TestEngine_CustomConditionEvaluator(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Engine) error
		context *Context
		want    bool
		wantErr bool
	}{
		{
			name: "custom time condition - allowed",
			setup: func(e *Engine) error {
				e.RegisterConditionEvaluator(CustomCondition, &timeConditionEvaluator{})
				return e.AddRule(NewRule().
					ForResource("api").
					WithAction("access").
					WithEffect(Allow).
					WithStructuredCondition("timeCheck", Condition{
						Type:      CustomCondition,
						Operation: In,
						Value:     []string{"morning", "afternoon"},
					}))
			},
			context: NewContext().WithEnvironment(map[string]interface{}{
				"time": "morning",
			}),
			want:    true,
			wantErr: false,
		},
		{
			name: "custom time condition - denied",
			setup: func(e *Engine) error {
				e.RegisterConditionEvaluator(CustomCondition, &timeConditionEvaluator{})
				return e.AddRule(NewRule().
					ForResource("api").
					WithAction("access").
					WithEffect(Allow).
					WithStructuredCondition("timeCheck", Condition{
						Type:      CustomCondition,
						Operation: In,
						Value:     []string{"morning", "afternoon"},
					}))
			},
			context: NewContext().WithEnvironment(map[string]interface{}{
				"time": "night",
			}),
			want:    false,
			wantErr: false,
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

			got, err := engine.IsAllowed("api", "access", tt.context)
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

	allowed, err := engine.IsAllowed("resource", "action", ctx)
	if err != nil {
		t.Errorf("IsAllowed() error = %v, want nil", err)
	}
	if allowed {
		t.Error("IsAllowed() should return false when no rules match")
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			rule := NewRule().
				ForResource("documents").
				WithAction("read").
				WithEffect(Allow).
				WithStructuredCondition("ownership", Condition{
					Type:      CustomCondition,
					Operation: Equals,
					Value:     true,
				})

			if err := engine.AddRule(rule); err != nil {
				t.Fatalf("Failed to add rule: %v", err)
			}

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

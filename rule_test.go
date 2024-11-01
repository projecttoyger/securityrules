package securityrules

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestRule_Creation(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *Rule
		validate func(*testing.T, *Rule)
	}{
		{
			name: "default values",
			setup: func() *Rule {
				return NewRule()
			},
			validate: func(t *testing.T, r *Rule) {
				if r.Type != ResourceRule {
					t.Errorf("Expected Type to be ResourceRule, got %v", r.Type)
				}
				if r.Severity != Low {
					t.Errorf("Expected Severity to be Low, got %v", r.Severity)
				}
				if r.Effect != Deny {
					t.Errorf("Expected Effect to be Deny, got %v", r.Effect)
				}
			},
		},
		{
			name: "full configuration",
			setup: func() *Rule {
				return NewRule().
					WithID("test-rule").
					WithName("Test Rule").
					WithDescription("Test rule description").
					WithType(KubernetesRule).
					WithSeverity(High).
					ForResource("pods").
					WithAction("create").
					WithEffect(Allow).
					WithMetadata("version", "v1")
			},
			validate: func(t *testing.T, r *Rule) {
				if r.ID != "test-rule" {
					t.Errorf("Expected ID to be test-rule, got %v", r.ID)
				}
				if r.Type != KubernetesRule {
					t.Errorf("Expected Type to be KubernetesRule, got %v", r.Type)
				}
				if r.Resource != "pods" {
					t.Errorf("Expected Resource to be pods, got %v", r.Resource)
				}
				if r.Action != "create" {
					t.Errorf("Expected Action to be create, got %v", r.Action)
				}
				if r.Effect != Allow {
					t.Errorf("Expected Effect to be Allow, got %v", r.Effect)
				}
				if r.Metadata["version"] != "v1" {
					t.Errorf("Expected metadata version to be v1, got %v", r.Metadata["version"])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.setup()
			tt.validate(t, rule)
		})
	}
}

func TestRule_Validation(t *testing.T) {
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
			err := tt.rule.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRule_Conditions(t *testing.T) {
	tests := []struct {
		name       string
		setup      func() *Rule
		conditions map[string]Condition
	}{
		{
			name: "basic condition",
			setup: func() *Rule {
				return NewRule().WithCondition("userRole", "admin")
			},
			conditions: map[string]Condition{
				"userRole": {
					Type:      "basic",
					Operation: "equals",
					Value:     "admin",
				},
			},
		},
		{
			name: "structured condition",
			setup: func() *Rule {
				return NewRule().WithStructuredCondition("userRole", Condition{
					Type:      "role",
					Operation: "in",
					Value:     []string{"admin", "superuser"},
					Message:   "User must be an admin or superuser",
				})
			},
			conditions: map[string]Condition{
				"userRole": {
					Type:      "role",
					Operation: "in",
					Value:     []string{"admin", "superuser"},
					Message:   "User must be an admin or superuser",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.setup()
			if !reflect.DeepEqual(rule.Conditions, tt.conditions) {
				t.Errorf("Conditions = %v, want %v", rule.Conditions, tt.conditions)
			}
		})
	}
}

func TestRule_JSON(t *testing.T) {
	originalRule := NewRule().
		WithID("test-rule").
		WithName("Test Rule").
		WithDescription("Test Description").
		WithType(KubernetesRule).
		WithSeverity(High).
		ForResource("pods").
		WithAction("create").
		WithEffect(Allow).
		WithMetadata("version", "v1").
		WithStructuredCondition("userRole", Condition{
			Type:      "role",
			Operation: "in",
			Value:     []string{"admin"},
			Message:   "Admin access required",
		})

	data, err := json.Marshal(originalRule)
	if err != nil {
		t.Fatalf("Failed to marshal rule: %v", err)
	}

	var unmarshaled Rule
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal rule: %v", err)
	}

	// Compare fields individually for better error messages
	if originalRule.ID != unmarshaled.ID {
		t.Errorf("ID mismatch: got %v, want %v", unmarshaled.ID, originalRule.ID)
	}
	if originalRule.Name != unmarshaled.Name {
		t.Errorf("Name mismatch: got %v, want %v", unmarshaled.Name, originalRule.Name)
	}
	if originalRule.Description != unmarshaled.Description {
		t.Errorf("Description mismatch: got %v, want %v", unmarshaled.Description, originalRule.Description)
	}
	if originalRule.Type != unmarshaled.Type {
		t.Errorf("Type mismatch: got %v, want %v", unmarshaled.Type, originalRule.Type)
	}
	if originalRule.Severity != unmarshaled.Severity {
		t.Errorf("Severity mismatch: got %v, want %v", unmarshaled.Severity, originalRule.Severity)
	}
	if originalRule.Resource != unmarshaled.Resource {
		t.Errorf("Resource mismatch: got %v, want %v", unmarshaled.Resource, originalRule.Resource)
	}
	if originalRule.Action != unmarshaled.Action {
		t.Errorf("Action mismatch: got %v, want %v", unmarshaled.Action, originalRule.Action)
	}
	if originalRule.Effect != unmarshaled.Effect {
		t.Errorf("Effect mismatch: got %v, want %v", unmarshaled.Effect, originalRule.Effect)
	}
	if !reflect.DeepEqual(originalRule.Conditions, unmarshaled.Conditions) {
		t.Errorf("Conditions mismatch:\ngot:  %#v\nwant: %#v", unmarshaled.Conditions, originalRule.Conditions)
	}
	if !reflect.DeepEqual(originalRule.Metadata, unmarshaled.Metadata) {
		t.Errorf("Metadata mismatch:\ngot:  %#v\nwant: %#v", unmarshaled.Metadata, originalRule.Metadata)
	}
}

func TestRule_Matches(t *testing.T) {
	tests := []struct {
		name     string
		rule     *Rule
		resource string
		action   string
		want     bool
	}{
		{
			name:     "exact match",
			rule:     NewRule().ForResource("pods").WithAction("create"),
			resource: "pods",
			action:   "create",
			want:     true,
		},
		{
			name:     "wildcard resource",
			rule:     NewRule().ForResource("*").WithAction("create"),
			resource: "pods",
			action:   "create",
			want:     true,
		},
		{
			name:     "wildcard action",
			rule:     NewRule().ForResource("pods").WithAction("*"),
			resource: "pods",
			action:   "delete",
			want:     true,
		},
		{
			name:     "no match",
			rule:     NewRule().ForResource("pods").WithAction("create"),
			resource: "services",
			action:   "delete",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.rule.matches(tt.resource, tt.action); got != tt.want {
				t.Errorf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCondition_JSON(t *testing.T) {
	tests := []struct {
		name      string
		condition Condition
	}{
		{
			name: "string value",
			condition: Condition{
				Type:      BasicCondition,
				Operation: Equals,
				Value:     "admin",
				Message:   "Must be admin",
			},
		},
		{
			name: "string slice value",
			condition: Condition{
				Type:      RoleCondition,
				Operation: In,
				Value:     []string{"admin", "superuser"},
				Message:   "Must be admin or superuser",
			},
		},
		{
			name: "bool value",
			condition: Condition{
				Type:      CustomCondition,
				Operation: Equals,
				Value:     true,
				Message:   "Must be true",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.condition)
			if err != nil {
				t.Fatalf("Failed to marshal condition: %v", err)
			}

			var unmarshaled Condition
			if err := json.Unmarshal(data, &unmarshaled); err != nil {
				t.Fatalf("Failed to unmarshal condition: %v", err)
			}

			if !reflect.DeepEqual(tt.condition, unmarshaled) {
				t.Errorf("JSON marshaling/unmarshaling didn't preserve data\nOriginal: %#v\nUnmarshaled: %#v", tt.condition, unmarshaled)
			}
		})
	}
}

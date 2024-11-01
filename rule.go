package securityrules

import (
	"encoding/json"
	"fmt"
)

// Rule represents a security policy rule with enhanced capabilities
type Rule struct {
	ID          string               `json:"id"`          // Unique identifier for the rule
	Name        string               `json:"name"`        // Human-readable name
	Description string               `json:"description"` // Detailed description
	Type        RuleType             `json:"type"`        // Type of the rule
	Severity    Severity             `json:"severity"`    // Impact severity
	Resource    string               `json:"resource"`    // Target resource
	Action      string               `json:"action"`      // Target action
	Effect      Effect               `json:"effect"`      // Allow/Deny
	Conditions  map[string]Condition `json:"conditions"`  // Rule conditions
	Metadata    map[string]string    `json:"metadata"`    // Additional metadata
}

// Custom marshaling types
type ruleAlias Rule

type ruleJSON struct {
	*ruleAlias
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Effect   string `json:"effect"`
}

// MarshalJSON implements the json.Marshaler interface
func (r *Rule) MarshalJSON() ([]byte, error) {
	type RuleJSON struct {
		ID          string               `json:"id"`
		Name        string               `json:"name"`
		Description string               `json:"description"`
		Type        string               `json:"type"`
		Severity    string               `json:"severity"`
		Resource    string               `json:"resource"`
		Action      string               `json:"action"`
		Effect      string               `json:"effect"`
		Conditions  map[string]Condition `json:"conditions"`
		Metadata    map[string]string    `json:"metadata"`
	}

	return json.Marshal(RuleJSON{
		ID:          r.ID,
		Name:        r.Name,
		Description: r.Description,
		Type:        string(r.Type),
		Severity:    string(r.Severity),
		Resource:    r.Resource,
		Action:      r.Action,
		Effect:      string(r.Effect),
		Conditions:  r.Conditions,
		Metadata:    r.Metadata,
	})
}

// UnmarshalJSON implements the json.Unmarshaler interface
func (r *Rule) UnmarshalJSON(data []byte) error {
	type RuleJSON struct {
		ID          string               `json:"id"`
		Name        string               `json:"name"`
		Description string               `json:"description"`
		Type        string               `json:"type"`
		Severity    string               `json:"severity"`
		Resource    string               `json:"resource"`
		Action      string               `json:"action"`
		Effect      string               `json:"effect"`
		Conditions  map[string]Condition `json:"conditions"`
		Metadata    map[string]string    `json:"metadata"`
	}

	var rj RuleJSON
	if err := json.Unmarshal(data, &rj); err != nil {
		return err
	}

	r.ID = rj.ID
	r.Name = rj.Name
	r.Description = rj.Description
	r.Type = RuleType(rj.Type)
	r.Severity = Severity(rj.Severity)
	r.Resource = rj.Resource
	r.Action = rj.Action
	r.Effect = Effect(rj.Effect)
	r.Conditions = rj.Conditions
	r.Metadata = rj.Metadata

	// Initialize maps if they're nil
	if r.Conditions == nil {
		r.Conditions = make(map[string]Condition)
	}
	if r.Metadata == nil {
		r.Metadata = make(map[string]string)
	}

	return nil
}

// NewRule creates a new Rule instance with default values
func NewRule() *Rule {
	return &Rule{
		Type:       ResourceRule,
		Severity:   Low,
		Effect:     Deny,
		Conditions: make(map[string]Condition),
		Metadata:   make(map[string]string),
	}
}

// ForResource sets the rule's resource
func (r *Rule) ForResource(resource string) *Rule {
	r.Resource = resource
	return r
}

// WithAction sets the rule's action
func (r *Rule) WithAction(action string) *Rule {
	r.Action = action
	return r
}

// WithEffect sets the rule's effect
func (r *Rule) WithEffect(effect Effect) *Rule {
	r.Effect = effect
	return r
}

// WithCondition adds a basic condition to the rule
func (r *Rule) WithCondition(key string, value interface{}) *Rule {
	r.Conditions[key] = Condition{
		Type:      BasicCondition,
		Operation: Equals,
		Value:     value,
	}
	return r
}

// WithStructuredCondition adds a structured condition to the rule
func (r *Rule) WithStructuredCondition(key string, condition Condition) *Rule {
	if err := condition.ValidateCondition(); err != nil {
		// Log error or handle it as appropriate for your use case
		return r
	}
	r.Conditions[key] = condition
	return r
}

// WithMetadata adds metadata to the rule
func (r *Rule) WithMetadata(key, value string) *Rule {
	r.Metadata[key] = value
	return r
}

// WithID sets the rule's ID
func (r *Rule) WithID(id string) *Rule {
	r.ID = id
	return r
}

// WithName sets the rule's name
func (r *Rule) WithName(name string) *Rule {
	r.Name = name
	return r
}

// WithDescription sets the rule's description
func (r *Rule) WithDescription(description string) *Rule {
	r.Description = description
	return r
}

// WithType sets the rule's type
func (r *Rule) WithType(ruleType RuleType) *Rule {
	r.Type = ruleType
	return r
}

// WithSeverity sets the rule's severity
func (r *Rule) WithSeverity(severity Severity) *Rule {
	r.Severity = severity
	return r
}

// validate checks if the rule is valid
func (r *Rule) validate() error {
	if r.Resource == "" {
		return &ErrInvalidRule{Message: "resource is required"}
	}
	if r.Action == "" {
		return &ErrInvalidRule{Message: "action is required"}
	}
	if r.Effect != Allow && r.Effect != Deny {
		return &ErrInvalidRule{Message: "effect must be either allow or deny"}
	}
	if r.Type == "" {
		return &ErrInvalidRule{Message: "rule type is required"}
	}

	// Validate all conditions
	for key, condition := range r.Conditions {
		if err := condition.ValidateCondition(); err != nil {
			return &ErrInvalidRule{Message: fmt.Sprintf("invalid condition '%s': %s", key, err.Error())}
		}
	}

	return nil
}

// matches checks if the rule matches the given resource and action
func (r *Rule) matches(resource, action string) bool {
	return (r.Resource == resource || r.Resource == "*") &&
		(r.Action == action || r.Action == "*")
}

// String returns a string representation of the rule
func (r *Rule) String() string {
	return fmt.Sprintf("Rule{ID: %s, Type: %s, Resource: %s, Action: %s, Effect: %s}",
		r.ID, r.Type, r.Resource, r.Action, r.Effect)
}

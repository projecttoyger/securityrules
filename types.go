package securityrules

import "encoding/json"

// RuleType defines the category of a security rule
type RuleType string

const (
	// KubernetesRule represents rules specific to Kubernetes resources
	KubernetesRule RuleType = "kubernetes"
	// NetworkRule represents network security rules
	NetworkRule RuleType = "network"
	// ResourceRule represents general resource access rules
	ResourceRule RuleType = "resource"
	// CustomRule represents user-defined custom rules
	CustomRule RuleType = "custom"
)

// Severity indicates the impact level of a rule violation
type Severity string

const (
	// Critical severity indicates immediate action required
	Critical Severity = "CRITICAL"
	// High severity indicates significant security risk
	High Severity = "HIGH"
	// Medium severity indicates moderate security risk
	Medium Severity = "MEDIUM"
	// Low severity indicates minor security concern
	Low Severity = "LOW"
)

// Effect defines whether a rule allows or denies access
type Effect string

const (
	// Allow grants access when rule conditions are met
	Allow Effect = "allow"
	// Deny refuses access when rule conditions are met
	Deny Effect = "deny"
)

// ConditionOperator defines the type of comparison operation
type ConditionOperator string

const (
	// Equals checks for exact match
	Equals ConditionOperator = "equals"
	// NotEquals checks for non-match
	NotEquals ConditionOperator = "notEquals"
	// In checks if value is in a set
	In ConditionOperator = "in"
	// NotIn checks if value is not in a set
	NotIn ConditionOperator = "notIn"
	// Contains checks if value contains substring/element
	Contains ConditionOperator = "contains"
	// Matches checks if value matches regex pattern
	Matches ConditionOperator = "matches"
)

// ConditionType defines the type of condition being evaluated
type ConditionType string

const (
	// BasicCondition represents simple equality checks
	BasicCondition ConditionType = "basic"
	// RoleCondition represents role-based checks
	RoleCondition ConditionType = "role"
	// K8sCondition represents Kubernetes-specific checks
	K8sCondition ConditionType = "k8s"
	// RegexCondition represents regex pattern matching
	RegexCondition ConditionType = "regex"
	// CustomCondition represents user-defined checks
	CustomCondition ConditionType = "custom"
)

// Condition represents a single evaluatable condition within a rule
type Condition struct {
	Type      ConditionType     `json:"type"`      // Type of the condition
	Operation ConditionOperator `json:"operation"` // Operation to perform
	Value     interface{}       `json:"value"`     // Expected value for comparison
	Message   string            `json:"message"`   // Custom message when condition fails
}

// MarshalJSON implements json.Marshaler
func (c Condition) MarshalJSON() ([]byte, error) {
	type ConditionAlias Condition
	return json.Marshal(struct {
		ConditionAlias
		Type      string `json:"type"`
		Operation string `json:"operation"`
	}{
		ConditionAlias: ConditionAlias(c),
		Type:           string(c.Type),
		Operation:      string(c.Operation),
	})
}

// UnmarshalJSON implements json.Unmarshaler
func (c *Condition) UnmarshalJSON(data []byte) error {
	type ConditionAlias Condition
	aux := struct {
		ConditionAlias
		Type      string          `json:"type"`
		Operation string          `json:"operation"`
		Value     json.RawMessage `json:"value"`
	}{}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	c.Type = ConditionType(aux.Type)
	c.Operation = ConditionOperator(aux.Operation)
	c.Message = aux.Message

	// Try to unmarshal Value as []string first
	var strSlice []string
	if err := json.Unmarshal(aux.Value, &strSlice); err == nil {
		c.Value = strSlice
		return nil
	}

	// If that fails, try as string
	var str string
	if err := json.Unmarshal(aux.Value, &str); err == nil {
		c.Value = str
		return nil
	}

	// If both fail, use the default unmarshaling
	var value interface{}
	if err := json.Unmarshal(aux.Value, &value); err != nil {
		return err
	}
	c.Value = value

	return nil
}

// ValidateCondition checks if a condition is properly configured
func (c *Condition) ValidateCondition() error {
	if c.Type == "" {
		return &ErrInvalidCondition{Message: "condition type is required"}
	}
	if c.Operation == "" {
		return &ErrInvalidCondition{Message: "condition operation is required"}
	}
	if c.Value == nil {
		return &ErrInvalidCondition{Message: "condition value is required"}
	}
	return nil
}

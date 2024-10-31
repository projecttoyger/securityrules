package securityrules

// Effect represents the rule effect type
type Effect string

const (
	// Allow represents an allowing effect
	Allow Effect = "allow"
	// Deny represents a denying effect
	Deny Effect = "deny"
)

// Rule represents a security rule
type Rule struct {
	resource   string
	action     string
	effect     Effect
	conditions map[string]interface{}
}

// NewRule creates a new Rule instance
func NewRule() *Rule {
	return &Rule{
		conditions: make(map[string]interface{}),
	}
}

// ForResource sets the rule's resource
func (r *Rule) ForResource(resource string) *Rule {
	r.resource = resource
	return r
}

// WithAction sets the rule's action
func (r *Rule) WithAction(action string) *Rule {
	r.action = action
	return r
}

// WithEffect sets the rule's effect
func (r *Rule) WithEffect(effect Effect) *Rule {
	r.effect = effect
	return r
}

// WithCondition adds a condition to the rule
func (r *Rule) WithCondition(key string, value interface{}) *Rule {
	r.conditions[key] = value
	return r
}

// validate checks if the rule is valid
func (r *Rule) validate() error {
	if r.resource == "" {
		return &ErrInvalidRule{Message: "resource is required"}
	}
	if r.action == "" {
		return &ErrInvalidRule{Message: "action is required"}
	}
	if r.effect != Allow && r.effect != Deny {
		return &ErrInvalidRule{Message: "effect must be either allow or deny"}
	}
	return nil
}

// matches checks if the rule matches the given resource and action
func (r *Rule) matches(resource, action string) bool {
	return (r.resource == resource || r.resource == "*") &&
		(r.action == action || r.action == "*")
}

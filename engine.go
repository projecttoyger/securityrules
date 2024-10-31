package securityrules

import "sync"

// Engine represents the security rules engine
type Engine struct {
	rules []Rule
	mu    sync.RWMutex
}

// NewEngine creates a new Engine instance
func NewEngine() *Engine {
	return &Engine{
		rules: make([]Rule, 0),
	}
}

// AddRule adds a rule to the engine
func (e *Engine) AddRule(rule *Rule) error {
	if err := rule.validate(); err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, *rule)
	return nil
}

// IsAllowed checks if an action is allowed
func (e *Engine) IsAllowed(resource, action string, ctx *Context) (bool, error) {
	if ctx == nil {
		return false, &ErrInvalidContext{Message: "context is required"}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	matchingRules := e.findMatchingRules(resource, action)
	if len(matchingRules) == 0 {
		return false, nil // Default deny
	}

	for _, rule := range matchingRules {
		allowed, err := e.evaluateRule(rule, ctx)
		if err != nil {
			return false, err
		}
		if !allowed {
			return false, nil
		}
	}

	return true, nil
}

// findMatchingRules finds all rules matching the resource and action
func (e *Engine) findMatchingRules(resource, action string) []Rule {
	var matching []Rule
	for _, rule := range e.rules {
		if rule.matches(resource, action) {
			matching = append(matching, rule)
		}
	}
	return matching
}

// evaluateRule evaluates a single rule against the context
func (e *Engine) evaluateRule(rule Rule, ctx *Context) (bool, error) {
	for key, condition := range rule.conditions {
		switch key {
		case "userRole":
			if !e.matchUserRole(ctx, condition) {
				return false, nil
			}
		case "resourceOwner":
			if !e.matchResourceOwner(ctx) {
				return false, nil
			}
			// Add more condition evaluators here
		}
	}

	return rule.effect == Allow, nil
}

// matchUserRole checks if the user has the required role
func (e *Engine) matchUserRole(ctx *Context, requiredRole interface{}) bool {
	// Try array format first
	if roles, ok := ctx.User()["roles"].([]string); ok {
		for _, role := range roles {
			if role == requiredRole.(string) {
				return true
			}
		}
	}

	// Try single role format
	if role, ok := ctx.User()["role"].(string); ok {
		if role == requiredRole.(string) {
			return true
		}
	}
	return false
}

// matchResourceOwner checks if the user owns the resource
func (e *Engine) matchResourceOwner(ctx *Context) bool {
	userID, userOK := ctx.User()["id"]
	resourceOwner, resourceOK := ctx.Resource()["owner"]
	return userOK && resourceOK && userID == resourceOwner
}

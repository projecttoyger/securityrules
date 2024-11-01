package securityrules

import (
	"fmt"
	"sync"
)

// Engine represents the security rules engine
type Engine struct {
	rules               []Rule
	conditionEvaluators map[ConditionType]ConditionEvaluator
	mu                  sync.RWMutex
}

// ConditionEvaluator defines the interface for condition evaluation
type ConditionEvaluator interface {
	Evaluate(condition Condition, ctx *Context) (bool, error)
}

// NewEngine creates a new Engine instance
func NewEngine() *Engine {
	engine := &Engine{
		rules:               make([]Rule, 0),
		conditionEvaluators: make(map[ConditionType]ConditionEvaluator),
	}

	// Register default evaluators
	engine.registerDefaultEvaluators()
	return engine
}

// RegisterConditionEvaluator registers a custom condition evaluator
func (e *Engine) RegisterConditionEvaluator(condType ConditionType, evaluator ConditionEvaluator) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.conditionEvaluators[condType] = evaluator
}

// AddRule adds a rule to the engine
func (e *Engine) AddRule(rule *Rule) error {
	if rule == nil {
		return NewInvalidRuleError("rule cannot be nil")
	}

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
		return false, NewInvalidContextError("context is required")
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
			return false, NewRuleEvaluationError(rule.ID, err.Error())
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
	for key, condition := range rule.Conditions {
		evaluator, exists := e.conditionEvaluators[condition.Type]
		if !exists {
			return false, fmt.Errorf("no evaluator registered for condition type: %s", condition.Type)
		}

		match, err := evaluator.Evaluate(condition, ctx)
		if err != nil {
			return false, NewInvalidConditionFieldError(key, err.Error())
		}
		if !match {
			return false, nil
		}
	}

	return rule.Effect == Allow, nil
}

// registerDefaultEvaluators sets up the built-in condition evaluators
func (e *Engine) registerDefaultEvaluators() {
	// Role evaluator
	e.RegisterConditionEvaluator(RoleCondition, &roleEvaluator{})

	// Basic evaluator
	e.RegisterConditionEvaluator(BasicCondition, &basicEvaluator{})

	// Resource owner evaluator
	e.RegisterConditionEvaluator(CustomCondition, &resourceOwnerEvaluator{})
}

// Built-in evaluators
type roleEvaluator struct{}

func (e *roleEvaluator) Evaluate(condition Condition, ctx *Context) (bool, error) {
	requiredRoles, ok := condition.Value.([]interface{})
	if !ok {
		// Try single role case
		if singleRole, ok := condition.Value.(string); ok {
			requiredRoles = []interface{}{singleRole}
		} else {
			return false, fmt.Errorf("invalid role format in condition")
		}
	}

	userRoles, ok := ctx.User()["roles"].([]string)
	if !ok {
		// Try interface slice
		if interfaceRoles, ok := ctx.User()["roles"].([]interface{}); ok {
			userRoles = make([]string, len(interfaceRoles))
			for i, v := range interfaceRoles {
				if str, ok := v.(string); ok {
					userRoles[i] = str
				} else {
					return false, fmt.Errorf("invalid role type in user context")
				}
			}
		} else {
			// Try single role
			if role, ok := ctx.User()["role"].(string); ok {
				userRoles = []string{role}
			} else {
				return false, fmt.Errorf("roles not found in context")
			}
		}
	}

	// Check if any of the user roles match any of the required roles
	for _, userRole := range userRoles {
		for _, reqRole := range requiredRoles {
			if reqStr, ok := reqRole.(string); ok {
				if userRole == reqStr {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

type basicEvaluator struct{}

func (e *basicEvaluator) Evaluate(condition Condition, ctx *Context) (bool, error) {
	switch condition.Operation {
	case Equals:
		return condition.Value == ctx.User()["value"], nil
	case NotEquals:
		return condition.Value != ctx.User()["value"], nil
	default:
		return false, fmt.Errorf("unsupported operation: %s", condition.Operation)
	}
}

type resourceOwnerEvaluator struct{}

func (e *resourceOwnerEvaluator) Evaluate(condition Condition, ctx *Context) (bool, error) {
	userID, userOK := ctx.User()["id"]
	resourceOwner, resourceOK := ctx.Resource()["owner"]
	return userOK && resourceOK && userID == resourceOwner, nil
}

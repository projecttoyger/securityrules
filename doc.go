// Package securityrules provides a flexible security rules engine for managing
// access control in Go applications.
//
// The package allows you to define security rules with conditions and evaluate
// them against a given context to determine if an action is allowed.
//
// Basic usage:
//
//	engine := securityrules.NewEngine()
//
//	rule := securityrules.NewRule().
//	    ForResource("documents").
//	    WithAction("read").
//	    WithEffect(securityrules.Allow)
//
//	engine.AddRule(rule)
//
//	ctx := securityrules.NewContext().
//	    WithUser(map[string]interface{}{"role": "admin"})
//
//	allowed, err := engine.IsAllowed("documents", "read", ctx)
package securityrules

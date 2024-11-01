// Package securityrules provides a flexible and extensible security rules engine.
package securityrules

// Basic usage:
//
//	// Create a new engine
//	engine := securityrules.NewEngine()
//
//	// Create a rule with role-based condition
//	rule := securityrules.NewRule().
//	    WithID("doc-access").             // Required: Unique identifier
//	    WithType(securityrules.ResourceRule).  // Required: Rule type
//	    ForResource("documents").         // Required: Target resource
//	    WithAction("read").              // Required: Target action
//	    WithEffect(securityrules.Allow).  // Required: Allow/Deny
//	    WithStructuredCondition("userRole", securityrules.Condition{
//	        Type:      securityrules.RoleCondition,
//	        Operation: securityrules.In,
//	        Value:     []interface{}{"admin", "editor"},
//	        Message:   "Must be admin or editor",
//	    })
//
//	// Add rule to engine
//	if err := engine.AddRule(rule); err != nil {
//	    log.Printf("Error adding rule: %v", err)
//	    return
//	}
//
//	// Create evaluation context
//	ctx := securityrules.NewContext().
//	    WithUser(map[string]interface{}{
//	        "id":    "user123",
//	        "roles": []interface{}{"admin"},
//	    })
//
//	// Check permission
//	allowed, err := engine.IsAllowed("documents", "read", ctx)
//	if err != nil {
//	    log.Printf("Error checking permission: %v", err)
//	    return
//	}
//
//	if allowed {
//	    fmt.Println("Access granted!")
//	} else {
//	    condition := rule.Conditions["userRole"]
//	    fmt.Printf("Access denied: %s\n", condition.Message)
//	}

// For more examples and detailed documentation, visit:
// https://pkg.go.dev/github.com/projecttoyger/securityrules

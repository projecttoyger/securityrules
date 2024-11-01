# Security Rules Library

A flexible and extensible security rules engine for Go applications.

## Features
- Resource and action-based matching
- Support for different rule types (Kubernetes, Network, Resource, Custom)
- Severity levels (Critical, High, Medium, Low)
- Structured conditions with custom operations
- Metadata support for additional context
- JSON marshaling/unmarshaling support

## Rule Type
The Rule type represents a security policy rule that can be used to control access to resources. It provides a flexible and extensible way to define security policies with various conditions and metadata. 

## Installation

```bash
go get github.com/projecttoyger/securityrules
```

## Quick Start

```go
    // Create a new engine
	engine := securityrules.NewEngine()

	// Create a rule for document access
	rule := securityrules.NewRule().
		WithID("doc-access-rule").
		WithName("Document Access Control").
		WithType(securityrules.ResourceRule).
		WithSeverity(securityrules.High).
		ForResource("documents").
		WithAction("read").
		WithEffect(securityrules.Allow).
		WithStructuredCondition("userRole", securityrules.Condition{
			Type:      securityrules.RoleCondition,
			Operation: securityrules.In,
			Value:     []string{"admin", "editor"},
			Message:   "User must be an admin or editor",
		}).
		WithMetadata("owner", "security-team")

	// Add the rule to the engine
	if err := engine.AddRule(rule); err != nil {
		fmt.Printf("Error adding rule: %v\n", err)
		return
	}

	// Create an evaluation context
	ctx := securityrules.NewContext().
		WithUser(map[string]interface{}{
			"id":    "user123",
			"roles": []string{"editor"},
		}).
		WithResource(map[string]interface{}{
			"id":    "doc1",
			"owner": "user123",
		}).
		WithEnvironment(map[string]interface{}{
			"time": time.Now(),
			"ip":   "192.168.1.1",
		})
	
	// Check permission
	allowed, err := engine.IsAllowed("documents", "read", ctx)
	if err != nil {
		fmt.Printf("Error checking permission: %v\n", err)
		return
	}

	if allowed {
		fmt.Println("Access granted!")
	} else {
		fmt.Println("Access denied.")
	}
```

## Documentation
See [GoDoc](https://pkg.go.dev/github.com/projecttoyger/securityrules) for detailed documentation.

## License
MIT License

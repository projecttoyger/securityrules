# Security Rules Library

A flexible and extensible security rules engine for Go applications.

## Features
- Define and evaluate security rules
- Support for complex conditions
- Context-based evaluation
- Default deny policy
- Thread-safe operations

## Installation


```bash
go get github.com/projecttoyger/securityrules
```

## Quick Start

```go
	engine := securityrules.NewEngine()

	// Add a rule - check the error
	rule := securityrules.NewRule().
		ForResource("documents").
		WithAction("read").
		WithEffect(securityrules.Allow).
		WithCondition("userRole", "admin")

	if err := engine.AddRule(rule); err != nil {
		fmt.Printf("Error adding rule: %v\n", err)
		return
	}

	// Create context - use "roles" as array
	ctx := securityrules.NewContext().
		WithUser(map[string]interface{}{
			"roles": []string{"admin"},
		}).
		WithResource(map[string]interface{}{
			"id": "doc1",
		})

		// Check permission
	allowed, err := engine.IsAllowed("documents", "read", ctx)
	if err != nil {
		fmt.Printf("Error checking permission: %v\n", err)
		return
	}
```

## Documentation
See [GoDoc](https://pkg.go.dev/github.com/projecttoyger/securityrules) for detailed documentation.

## License
MIT License

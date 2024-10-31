```markdown
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

// Add a rule
rule := securityrules.NewRule().
    ForResource("documents").
    WithAction("read").
    WithEffect(securityrules.Allow).
    WithCondition("userRole", "admin")

engine.AddRule(rule)

// Create context
ctx := securityrules.NewContext().
    WithUser(map[string]interface{}{"role": "admin"}).
    WithResource(map[string]interface{}{"id": "doc1"})

// Check permission
allowed, err := engine.IsAllowed("documents", "read", ctx)
```

## Documentation
See [GoDoc](https://pkg.go.dev/github.com/projecttoyger/securityrules) for detailed documentation.

## License
MIT License

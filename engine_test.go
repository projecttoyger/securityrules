package securityrules

import (
	"testing"
)

func TestEngine_AddRule(t *testing.T) {
	tests := []struct {
		name    string
		rule    *Rule
		wantErr bool
	}{
		{
			name: "valid rule",
			rule: NewRule().
				ForResource("documents").
				WithAction("read").
				WithEffect(Allow),
			wantErr: false,
		},
		{
			name: "missing resource",
			rule: NewRule().
				WithAction("read").
				WithEffect(Allow),
			wantErr: true,
		},
		{
			name: "missing action",
			rule: NewRule().
				ForResource("documents").
				WithEffect(Allow),
			wantErr: true,
		},
		{
			name: "invalid effect",
			rule: NewRule().
				ForResource("documents").
				WithAction("read").
				WithEffect("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			err := engine.AddRule(tt.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("AddRule() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngine_IsAllowed(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*Engine)
		context  *Context
		resource string
		action   string
		want     bool
		wantErr  bool
	}{
		{
			name: "allowed for admin",
			setup: func(e *Engine) {
				e.AddRule(NewRule().
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow).
					WithCondition("userRole", "admin"))
			},
			context: NewContext().WithUser(map[string]interface{}{
				"roles": []string{"admin"},
			}),
			resource: "documents",
			action:   "read",
			want:     true,
			wantErr:  false,
		},
		{
			name: "denied for non-admin",
			setup: func(e *Engine) {
				e.AddRule(NewRule().
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow).
					WithCondition("userRole", "admin"))
			},
			context: NewContext().WithUser(map[string]interface{}{
				"roles": []string{"user"},
			}),
			resource: "documents",
			action:   "read",
			want:     false,
			wantErr:  false,
		},
		{
			name: "nil context",
			setup: func(e *Engine) {
				e.AddRule(NewRule().
					ForResource("documents").
					WithAction("read").
					WithEffect(Allow))
			},
			context:  nil,
			resource: "documents",
			action:   "read",
			want:     false,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewEngine()
			if tt.setup != nil {
				tt.setup(engine)
			}

			got, err := engine.IsAllowed(tt.resource, tt.action, tt.context)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsAllowed() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

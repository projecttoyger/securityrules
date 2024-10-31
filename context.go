package securityrules

// Context represents the security evaluation context
type Context struct {
	user        map[string]interface{}
	resource    map[string]interface{}
	environment map[string]interface{}
}

// NewContext creates a new Context instance
func NewContext() *Context {
	return &Context{
		user:        make(map[string]interface{}),
		resource:    make(map[string]interface{}),
		environment: make(map[string]interface{}),
	}
}

// WithUser sets the user context
func (c *Context) WithUser(user map[string]interface{}) *Context {
	c.user = user
	return c
}

// WithResource sets the resource context
func (c *Context) WithResource(resource map[string]interface{}) *Context {
	c.resource = resource
	return c
}

// WithEnvironment sets the environment context
func (c *Context) WithEnvironment(env map[string]interface{}) *Context {
	c.environment = env
	return c
}

// User returns the user context
func (c *Context) User() map[string]interface{} {
	return c.user
}

// Resource returns the resource context
func (c *Context) Resource() map[string]interface{} {
	return c.resource
}

// Environment returns the environment context
func (c *Context) Environment() map[string]interface{} {
	return c.environment
}

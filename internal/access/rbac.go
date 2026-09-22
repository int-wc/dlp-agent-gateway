package access

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

type RBAC struct {
	enforcer *casbin.Enforcer
}

func NewRBAC() (*RBAC, error) {
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
`)
	if err != nil {
		return nil, err
	}
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		return nil, err
	}
	_, _ = enforcer.AddPolicy("viewer", "/v1/admin/*", "GET")
	_, _ = enforcer.AddPolicy("operator", "/v1/admin/audits/:id/feedback", "PUT")
	_, _ = enforcer.AddPolicy("operator", "/v1/admin/exceptions/:id/:action", "POST")
	_, _ = enforcer.AddPolicy("operator", "/v1/admin/incidents/:id", "PUT")
	_, _ = enforcer.AddPolicy("operator", "/v1/admin/incidents/:id/notes", "POST")
	_, _ = enforcer.AddPolicy("admin", "/v1/admin/*", "(GET|POST|PUT|DELETE)")
	_, _ = enforcer.AddGroupingPolicy("operator", "viewer")
	_, _ = enforcer.AddGroupingPolicy("admin", "operator")
	return &RBAC{enforcer: enforcer}, nil
}

func (r *RBAC) Allowed(role, path, method string) bool {
	if r == nil || r.enforcer == nil {
		return false
	}
	allowed, err := r.enforcer.Enforce(role, path, method)
	return err == nil && allowed
}

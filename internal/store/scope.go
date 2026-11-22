package store

import (
	"context"
	"strings"
)

// Group-limited users (operators and viewers restricted to some groups) see
// only the hosts of those groups. The web layer puts the limit into the
// request context with WithScope; every query that lists or reads hosts,
// findings, updates, jobs or notifications applies it. Background work
// (scanner, notifier, schedules) runs without a scope and sees everything.

type scopeKey struct{}

// WithScope limits queries made with ctx to the hosts of the given groups.
// An empty list allows no hosts.
func WithScope(ctx context.Context, groupIDs []int64) context.Context {
	ids := append([]int64{}, groupIDs...)
	return context.WithValue(ctx, scopeKey{}, ids)
}

// ScopeFrom returns the group limit of ctx; ok is false when unrestricted.
func ScopeFrom(ctx context.Context) (groupIDs []int64, ok bool) {
	ids, ok := ctx.Value(scopeKey{}).([]int64)
	return ids, ok
}

// hostScope returns an SQL condition limiting the host id column col to the
// scope of ctx, and its arguments; "" when unrestricted.
func hostScope(ctx context.Context, col string) (string, []any) {
	ids, ok := ScopeFrom(ctx)
	if !ok {
		return "", nil
	}
	if len(ids) == 0 {
		return "1 = 0", nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return col + ` IN (SELECT host_id FROM host_group_members WHERE group_id IN (?` + strings.Repeat(",?", len(ids)-1) + `))`, args
}

// andScope appends the scope condition to a WHERE clause ("" or " WHERE ...").
func andScope(ctx context.Context, where string, args []any, col string) (string, []any) {
	cond, cargs := hostScope(ctx, col)
	if cond == "" {
		return where, args
	}
	if where == "" {
		return " WHERE " + cond, cargs
	}
	return where + " AND " + cond, append(args, cargs...)
}

// groupScope limits a group id column to the scope of ctx.
func groupScope(ctx context.Context, col string) (string, []any) {
	ids, ok := ScopeFrom(ctx)
	if !ok {
		return "", nil
	}
	if len(ids) == 0 {
		return "1 = 0", nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return col + ` IN (?` + strings.Repeat(",?", len(ids)-1) + `)`, args
}

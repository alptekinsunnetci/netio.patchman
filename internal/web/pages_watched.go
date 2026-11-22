package web

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"netio.patchman/internal/store"
)

// starArgs feeds the "star" template: a watch/unwatch toggle for a package
// that returns to the current page.
type starArgs struct {
	Name, CSRF, Back string
	On               bool
}

// watchedSet returns the signed-in user's watched package names as a set.
func (s *Server) watchedSet(ctx context.Context, r *http.Request) map[string]bool {
	set := map[string]bool{}
	sess := sessionFrom(r)
	if sess == nil {
		return set
	}
	names, _ := s.st.WatchedNames(ctx, sess.user.ID)
	for _, n := range names {
		set[n] = true
	}
	return set
}

// watchToggle adds or removes a package on the user's own watch list.
func (s *Server) watchToggle(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	name := strings.TrimSpace(r.PostFormValue("name"))
	back := safeNext(r.PostFormValue("back"))
	if !validPackageView(name) {
		s.redirect(w, r, back, "error", s.l.T("watch.error.invalid"))
		return
	}
	if r.PostFormValue("watch") == "0" {
		if err := s.st.UnwatchPackage(r.Context(), sess.user.ID, name); err != nil {
			s.serverError(w, r, err)
			return
		}
		s.redirect(w, r, back, "success", s.l.T("watch.removed", "package", name))
		return
	}
	err := s.st.WatchPackage(r.Context(), sess.user.ID, name)
	if errors.Is(err, store.ErrLimit) {
		s.redirect(w, r, back, "error", s.l.T("watch.error.limit", "max", store.MaxWatchedPerUser))
		return
	}
	if err != nil {
		s.serverError(w, r, err)
		return
	}
	s.redirect(w, r, back, "success", s.l.T("watch.added", "package", name))
}

## What and why

<!-- What does this change, and which problem does it solve? Link the issue: "Closes #123". -->

## How it was tested

<!-- Commands you ran, screenshots of changed pages, agents/OSes you tried. -->

## Checklist

- [ ] `go test ./...` passes (and on PostgreSQL if store queries changed: see CONTRIBUTING.md)
- [ ] `gofmt` and `go vet ./...` are clean
- [ ] New user-visible text is in all four catalogs (`internal/i18n/locales/*.json`), no literal UI text in code or templates
- [ ] Schema changes add the same numbered migration to `migrations/` and `migrations/postgres/`; no applied migration was edited
- [ ] Docs updated where behavior changed (README, `docs/`, API fields in `docs/api.md`)
- [ ] CVE data, package names and versions are shown verbatim (never translated or rewritten)

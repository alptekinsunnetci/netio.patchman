# Contributing to netio.patchman

🇬🇧 **English** · 🇹🇷 [Türkçe](CONTRIBUTING.tr.md) · ⏱️ Reading time: about 10 minutes

Thanks for helping! This guide gets you from a fresh clone to a merged pull request: setting up the development
environment, running the server and an agent, running the tests and the rules the code base follows.

- New here? Pick an issue labeled
  [**good first issue**](https://github.com/alptekinsunnetci/netio.patchman/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
  or [**help wanted**](https://github.com/alptekinsunnetci/netio.patchman/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
  and leave a comment that you are working on it.
- Have an idea? Open a [feature request](https://github.com/alptekinsunnetci/netio.patchman/issues/new?template=feature_request.yml)
  before writing a large change, so we can agree on the approach.
- Found a security issue? Do **not** open an issue; see
  [Reporting a vulnerability](docs/architecture-and-security.md#12-reporting-a-vulnerability).
- Try the interface without installing anything: [live demo](https://alptekinsunnetci.github.io/netio.patchman/demo/).
- Issues and pull requests can be written in English or Turkish.

## 1. Development environment

| Tool | Version | Needed for |
|---|---|---|
| [Go](https://go.dev/dl/) | 1.26 (see `go.mod`) | Everything. Builds are pure Go (`CGO_ENABLED=0`), no C compiler needed |
| Git | any recent | Cloning, the upgrade test |
| Docker with Compose v2 | optional | The full stack, PostgreSQL for tests, image builds |
| gcc | optional | `go test -race` (the race detector needs cgo) |
| A Linux VM or WSL | optional | Running a real agent (it needs root and a package manager) |

```sh
git clone https://github.com/alptekinsunnetci/netio.patchman.git
cd netio.patchman
go build ./...          # server, agent and all packages
go test ./...           # about two minutes on a laptop
```

Windows works as a development machine (the maintainers use it). Keep shell scripts, the systemd unit and the OpenRC
script in LF line endings; CI checks it.

## 2. Running the server locally

The quickest way is SQLite in a local data directory:

```sh
# Linux / macOS / WSL
PATCHMAN_DATABASE_URL=sqlite PATCHMAN_DATA_DIR=./data PATCHMAN_HTTP_ADDR=127.0.0.1:8080 \
PATCHMAN_BASE_URL=http://127.0.0.1:8080 go run ./cmd/netio-patchman-server
```

```powershell
# Windows PowerShell
$env:PATCHMAN_DATABASE_URL='sqlite'; $env:PATCHMAN_DATA_DIR='.\data'; $env:PATCHMAN_HTTP_ADDR='127.0.0.1:8080'
$env:PATCHMAN_BASE_URL='http://127.0.0.1:8080'; go run ./cmd/netio-patchman-server
```

Open <http://127.0.0.1:8080/setup> and create the first administrator. Useful variables while developing:

| Variable | Effect |
|---|---|
| `PATCHMAN_LOG_LEVEL=debug` | Verbose logs |
| `PATCHMAN_UPDATE_CHECK_URL=off` | No release check against GitHub |
| `PATCHMAN_KEV_URL=off`, `PATCHMAN_EPSS_URL=off`, `PATCHMAN_EOL_URL=off`, `PATCHMAN_MSRC_URL=off` | No feed downloads (faster start, offline work) |
| `PATCHMAN_LOCALE=en-US` | Default language for e-mails and logs (the UI language is chosen per user) |
| `PATCHMAN_AGENT_DIST_DIR=./dist/agent` | Agent binaries the server distributes (`scripts/build-agent.sh` fills it) |

The full stack with PostgreSQL, as users run it: `docker compose up -d --build` (see [docs/installation.md](docs/installation.md)).

## 3. Running an agent against your server

The agent reads package databases and applies updates, so run it on a disposable Linux VM or WSL distribution as root:

```sh
GOOS=linux GOARCH=amd64 go build -o netio-patchman-agent ./cmd/netio-patchman-agent
cat > agent.env <<'EOF'
PATCHMAN_SERVER_URL=http://<your machine's IP>:8080
PATCHMAN_ENROLLMENT_TOKEN=<token from the Agents page>
PATCHMAN_STATE_DIR=/tmp/np-agent
EOF
sudo ./netio-patchman-agent -config ./agent.env -debug
```

The host appears in the server inventory within a minute. `PATCHMAN_REMOTE_UPDATES=false` in `agent.env` keeps it
inventory-only while you experiment. The server must listen on an address the VM can reach (for example
`PATCHMAN_HTTP_ADDR=0.0.0.0:8080`).

## 4. Running the tests

| What | Command |
|---|---|
| Everything (SQLite, end-to-end web tests with a fake OSV server) | `go test ./...` |
| One package or test | `go test ./internal/compliance/ -run TestCatalogKeys -v` |
| Same suite on PostgreSQL (every test gets its own schema) | see below |
| Race detector | `CGO_ENABLED=1 go test -race ./...` |
| Static checks | `gofmt -l cmd internal deploy` (must print nothing), `go vet ./...`, `GOOS=windows go vet ./...` |
| Cross builds | `GOOS=linux GOARCH=arm64 go build ./...`, `GOOS=windows go build ./...` |
| Upgrade, migration and restore (as in CI) | `bash scripts/ci/upgrade-restore.sh` (needs PostgreSQL, `psql`, release tags) |
| Against the real OSV.dev API | `go test -tags live -run Live -v ./internal/scanner/` |
| Real Windows Update search (Windows only) | `go test -tags live -run LiveWindows -v ./internal/agent/` |

PostgreSQL for tests:

```sh
docker run -d --name np-test-pg -p 55432:5432 -e POSTGRES_USER=np -e POSTGRES_PASSWORD=np -e POSTGRES_DB=np \
  -e POSTGRES_INITDB_ARGS="--encoding=UTF8 --locale=C" postgres:17-alpine
PATCHMAN_TEST_DATABASE_URL=postgres://np:np@127.0.0.1:55432/np?sslmode=disable go test ./...
```

**Continuous integration** runs on every pull request: format and vet, tests on SQLite with the race detector, on
PostgreSQL 17 and on Windows, builds for Linux amd64/arm64 and Windows amd64, the Docker image and a Compose start-up,
the upgrade/restore test, govulncheck, dependency review and a container image scan. A pull request needs a green run.

## 5. Where things are

| Path | Contents |
|---|---|
| `cmd/netio-patchman-server`, `cmd/netio-patchman-agent` | Entry points (server sub-commands: `backup`, `restore`, `reset-password`, `reset-mfa`, `healthcheck`) |
| `internal/agent` | Collectors (apt, dnf/yum, zypper, apk, Windows Update, winget), job runner, self-update, monitoring |
| `internal/protocol` | The agent ↔ server JSON contract and input validation |
| `internal/api` | Agent API (register, check-in, report, job results) |
| `internal/web` | Web pages, templates, static files, sessions, REST API |
| `internal/store` | All SQL; migrations in `internal/store/migrations/` (SQLite) and `migrations/postgres/` |
| `internal/scanner` | OSV, KEV, EPSS, Microsoft MSRC; version comparison and ecosystem mapping |
| `internal/compliance` | Compliance & audit: framework profiles, checks, report engine, exports |
| `internal/i18n/locales` | Message catalogs: `tr-TR`, `en-US`, `de-DE`, `ru-RU` |
| `deploy/` | Agent install scripts, systemd/OpenRC units, the updater container |
| `docs/` | Installation and user guides (Turkish), API, [architecture and security model](docs/architecture-and-security.md) |

Read the [architecture and security model](docs/architecture-and-security.md) before changing anything that touches the
agent protocol, authentication or stored secrets.

## 6. Rules the code base follows

**Text and languages**

- Every user-visible string (pages, e-mails, errors, logs, CLI output, agent job messages) comes from the catalogs in
  `internal/i18n/locales/`. Add new keys to **all four** catalogs; `TestCatalogsMatch` and `TestReferencedKeysExist`
  fail otherwise. No literal UI text in Go code or templates.
- Code identifiers, database columns, API fields and code comments are English.
- **Vulnerability data is never translated or rewritten**: CVE ids, official titles and descriptions, CVSS scores and
  vectors, package names and versions are shown exactly as the source publishes them.

**Database**

- Every query must run on both SQLite and PostgreSQL. Write portable SQL with `?` placeholders; use `ON CONFLICT`,
  `RETURNING id`, `lower(col)`, `CASE` expressions and `NULLS LAST` as the existing code does.
- A schema change is a new numbered migration in **both** `migrations/` and `migrations/postgres/`. Never edit a
  migration that has been released.
- Queries that read hosts, findings, jobs or notifications must apply the group scope (`hostScope`, `andScope`).

**Security**

- The agent never listens on a port and never runs a shell. Jobs use fixed package manager commands; validate package
  and service names on both sides (`protocol.ValidPackageName`, `ValidServiceName`).
- Store only hashes of tokens and secrets. Every POST behind a login checks the CSRF token and the Origin.
- The Content Security Policy forbids inline scripts and styles: put behavior in `internal/web/static/app.js` and styles
  in `app.css`; load nothing from other hosts.

**Style**

- `gofmt`, small focused functions, comments that explain why. Look at a neighboring file and follow its patterns.
- Times are stored as UTC Unix seconds and displayed through the formatter.
- The product name is always written `netio.patchman` (lower case).

## 7. Pull requests

1. Fork, create a branch (`feature/short-name` or `fix/short-name`), keep it focused on one change.
2. Add or update tests for the behavior you change.
3. Run `go test ./...`, `gofmt` and `go vet` locally; for SQL changes also run the suite on PostgreSQL.
4. Update the docs when behavior changes (README, `docs/`, `docs/api.md` and `docs/api.en.md` for API fields; keep the Turkish and English docs in step).
5. Open the pull request and fill in the template. Screenshots help for interface changes.

Releases are cut by the maintainer: `VERSION` is bumped, the release commit is tagged `v<VERSION>` and published as a
GitHub release, and agents update themselves from the new server.

## 8. License

netio.patchman is licensed under the Apache License 2.0 with the Commons Clause (see [LICENSE](LICENSE)). By
submitting a contribution you agree that it is licensed under the same terms.

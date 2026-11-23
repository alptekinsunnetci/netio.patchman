package store

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"

	"netio.patchman/internal/protocol"
)

// SaveJobInventory stores the host's current package inventory for a job
// (called when a package job is dispatched).
func (s *Store) SaveJobInventory(ctx context.Context, jobID, hostID int64) error {
	pkgs, err := s.HostPackages(ctx, hostID)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(pkgs)
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	if err := zw.Close(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO job_inventory (job_id, host_id, data, created_at) VALUES (?, ?, ?, ?) ON CONFLICT (job_id) DO NOTHING`,
		jobID, hostID, base64.StdEncoding.EncodeToString(buf.Bytes()), now())
	return err
}

// JobInventory returns the inventory stored for a job (ErrNotFound without).
func (s *Store) JobInventory(ctx context.Context, jobID int64) ([]protocol.Package, error) {
	var data string
	err := s.db.QueryRowContext(ctx, `SELECT data FROM job_inventory WHERE job_id = ?`, jobID).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	plain, err := io.ReadAll(io.LimitReader(zr, 64<<20))
	if err != nil {
		return nil, err
	}
	var pkgs []protocol.Package
	return pkgs, json.Unmarshal(plain, &pkgs)
}

// AddHostExcludes appends package names to a host's own exclusion list
// (not its groups').
func (s *Store) AddHostExcludes(ctx context.Context, hostID int64, names []string) error {
	var raw string
	if err := s.db.QueryRowContext(ctx, `SELECT exclude_packages FROM hosts WHERE id = ?`, hostID).Scan(&raw); err != nil {
		return err
	}
	cur, _ := protocol.ParseExcludePatterns(raw)
	for _, n := range names {
		if !protocol.Excluded(cur, n) {
			cur = append(cur, n)
		}
	}
	list, _ := protocol.ParseExcludePatterns(joinComma(cur))
	return s.SetHostExclude(ctx, hostID, list)
}

func joinComma(s []string) string {
	var b bytes.Buffer
	for i, x := range s {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(x)
	}
	return b.String()
}

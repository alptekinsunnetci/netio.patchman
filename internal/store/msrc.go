package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// MSRCKB returns the cached Security Update Guide lookup of a KB number
// (JSON written by the scanner) and when it was fetched.
func (s *Store) MSRCKB(ctx context.Context, kb string) (data []byte, fetchedAt time.Time, err error) {
	var f int64
	err = s.db.QueryRowContext(ctx, `SELECT data, fetched_at FROM msrc_kb_cache WHERE kb = ?`, kb).Scan(&data, &f)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	return data, fromTS(f), nil
}

// SaveMSRCKB stores a KB lookup.
func (s *Store) SaveMSRCKB(ctx context.Context, kb string, data []byte) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO msrc_kb_cache (kb, data, fetched_at) VALUES (?, ?, ?)
		ON CONFLICT (kb) DO UPDATE SET data = excluded.data, fetched_at = excluded.fetched_at`, kb, string(data), now())
	return err
}

// PruneMSRCKB removes KB lookups fetched before the cutoff.
func (s *Store) PruneMSRCKB(ctx context.Context, olderThan time.Duration) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM msrc_kb_cache WHERE fetched_at < ?`, now()-int64(olderThan.Seconds()))
	return err
}

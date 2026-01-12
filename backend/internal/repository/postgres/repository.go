package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/domain"
)

type Repository struct {
	pool *pgxpool.Pool
}

func NewRepository(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool}
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func (r *Repository) GetTotalSize(ctx context.Context) (int64, error) {
	var totalSize int64
	err := r.pool.QueryRow(ctx, `SELECT COALESCE(SUM(size), 0) FROM inodes`).Scan(&totalSize)
	if err != nil {
		return 0, err
	}
	return totalSize, nil
}

func (r *Repository) Lookup(ctx context.Context, parentIno int64, name string) (*domain.Inode, error) {
	query := `
		SELECT i.ino, i.mode, i.size, i.nlink, i.created_at, i.updated_at
		FROM dir_entries d
		JOIN inodes i ON d.child_ino = i.ino
		WHERE d.parent_ino = $1 AND d.name = $2
	`

	var inode domain.Inode
	err := r.pool.QueryRow(ctx, query, parentIno, name).Scan(
		&inode.Ino, &inode.Mode, &inode.Size,
		&inode.Nlink, &inode.CreatedAt, &inode.UpdatedAt,
	)

	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	return &inode, nil
}

func (r *Repository) List(ctx context.Context, parentIno int64) ([]domain.DirEntry, error) {
	query := `
		SELECT d.parent_ino, d.name, d.child_ino, i.mode
		FROM dir_entries d
		JOIN inodes i ON d.child_ino = i.ino
		WHERE d.parent_ino = $1
		ORDER BY d.name
	`

	rows, err := r.pool.Query(ctx, query, parentIno)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []domain.DirEntry
	for rows.Next() {
		var e domain.DirEntry
		if err := rows.Scan(&e.ParentIno, &e.Name, &e.ChildIno, &e.Mode); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	return entries, rows.Err()
}

func (r *Repository) Create(ctx context.Context, parentIno int64, name string, mode uint32) (*domain.Inode, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var inode domain.Inode
	err = tx.QueryRow(ctx, `
		INSERT INTO inodes (mode, size, nlink)
		VALUES ($1, 0, 1)
		RETURNING ino, mode, size, nlink, created_at, updated_at
	`, mode).Scan(&inode.Ino, &inode.Mode, &inode.Size, &inode.Nlink, &inode.CreatedAt, &inode.UpdatedAt)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO dir_entries (parent_ino, name, child_ino)
		VALUES ($1, $2, $3)
	`, parentIno, name, inode.Ino)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrExists
		}
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO file_content (ino, data)
		VALUES ($1, ''::bytea)
	`, inode.Ino)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &inode, nil
}

func (r *Repository) Mkdir(ctx context.Context, parentIno int64, name string, mode uint32) (*domain.Inode, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var inode domain.Inode
	err = tx.QueryRow(ctx, `
		INSERT INTO inodes (mode, size, nlink)
		VALUES ($1, 0, 2)
		RETURNING ino, mode, size, nlink, created_at, updated_at
	`, mode).Scan(&inode.Ino, &inode.Mode, &inode.Size, &inode.Nlink, &inode.CreatedAt, &inode.UpdatedAt)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO dir_entries (parent_ino, name, child_ino)
		VALUES ($1, $2, $3)
	`, parentIno, name, inode.Ino)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrExists
		}
		return nil, err
	}

	_, err = tx.Exec(ctx, `
		UPDATE inodes SET nlink = nlink + 1 WHERE ino = $1
	`, parentIno)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &inode, nil
}

func (r *Repository) Unlink(ctx context.Context, parentIno int64, name string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var childIno int64
	var mode uint32
	err = tx.QueryRow(ctx, `
		SELECT d.child_ino, i.mode
		FROM dir_entries d
		JOIN inodes i ON d.child_ino = i.ino
		WHERE d.parent_ino = $1 AND d.name = $2
		FOR UPDATE OF d, i
	`, parentIno, name).Scan(&childIno, &mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}

	if (mode & domain.S_IFMT) == domain.S_IFDIR {
		return domain.ErrIsDirectory
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM dir_entries
		WHERE parent_ino = $1 AND name = $2
	`, parentIno, name)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		UPDATE inodes SET nlink = nlink - 1, updated_at = NOW()
		WHERE ino = $1
	`, childIno)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM file_content WHERE ino = $1
		AND NOT EXISTS (SELECT 1 FROM inodes WHERE ino = $1 AND nlink > 0)
	`, childIno)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM inodes WHERE ino = $1 AND nlink <= 0
	`, childIno)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *Repository) Rmdir(ctx context.Context, parentIno int64, name string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var childIno int64
	var mode uint32
	err = tx.QueryRow(ctx, `
		SELECT d.child_ino, i.mode
		FROM dir_entries d
		JOIN inodes i ON d.child_ino = i.ino
		WHERE d.parent_ino = $1 AND d.name = $2
		FOR UPDATE OF d, i
	`, parentIno, name).Scan(&childIno, &mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}

	if (mode & domain.S_IFMT) != domain.S_IFDIR {
		return domain.ErrNotDirectory
	}

	var count int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM dir_entries WHERE parent_ino = $1
	`, childIno).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return domain.ErrNotEmpty
	}

	_, err = tx.Exec(ctx, `
		DELETE FROM dir_entries WHERE parent_ino = $1 AND name = $2
	`, parentIno, name)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `DELETE FROM inodes WHERE ino = $1`, childIno)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		UPDATE inodes SET nlink = nlink - 1, updated_at = NOW()
		WHERE ino = $1
	`, parentIno)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (r *Repository) Read(ctx context.Context, ino int64, offset, size int64) ([]byte, int64, error) {
	var data []byte
	err := r.pool.QueryRow(ctx, `
		SELECT SUBSTRING(data FROM $2 FOR $3)
		FROM file_content
		WHERE ino = $1
	`, ino, offset+1, size).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, domain.ErrNotFound
	}
	if err != nil {
		return nil, 0, err
	}

	return data, int64(len(data)), nil
}

func (r *Repository) Write(ctx context.Context, ino int64, offset int64, data []byte) (int64, int64, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)

	var currentData []byte
	err = tx.QueryRow(ctx, `
		SELECT data FROM file_content WHERE ino = $1 FOR UPDATE
	`, ino).Scan(&currentData)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, domain.ErrNotFound
	}
	if err != nil {
		return 0, 0, err
	}

	newLen := offset + int64(len(data))
	if int64(len(currentData)) < newLen {
		extended := make([]byte, newLen)
		copy(extended, currentData)
		currentData = extended
	}

	copy(currentData[offset:], data)

	_, err = tx.Exec(ctx, `
		UPDATE file_content SET data = $2 WHERE ino = $1
	`, ino, currentData)
	if err != nil {
		return 0, 0, err
	}

	newSize := int64(len(currentData))
	_, err = tx.Exec(ctx, `
		UPDATE inodes SET size = $2, updated_at = NOW() WHERE ino = $1
	`, ino, newSize)
	if err != nil {
		return 0, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}

	return int64(len(data)), newSize, nil
}

func (r *Repository) Link(ctx context.Context, ino int64, newParentIno int64, newName string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var mode uint32
	err = tx.QueryRow(ctx, `
		SELECT mode FROM inodes WHERE ino = $1 FOR UPDATE
	`, ino).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}

	if (mode & domain.S_IFMT) == domain.S_IFDIR {
		return domain.ErrPermission
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO dir_entries (parent_ino, name, child_ino)
		VALUES ($1, $2, $3)
	`, newParentIno, newName, ino)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrExists
		}
		return err
	}

	_, err = tx.Exec(ctx, `
		UPDATE inodes SET nlink = nlink + 1, updated_at = NOW()
		WHERE ino = $1
	`, ino)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

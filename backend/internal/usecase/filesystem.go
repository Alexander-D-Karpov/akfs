package usecase

import (
	"context"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/domain"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/repository/postgres"
)

type FilesystemService interface {
	Lookup(ctx context.Context, parentIno int64, name string) (*domain.Inode, error)
	List(ctx context.Context, parentIno int64) ([]domain.DirEntry, error)
	Create(ctx context.Context, parentIno int64, name string, mode uint32) (*domain.Inode, error)
	Mkdir(ctx context.Context, parentIno int64, name string, mode uint32) (*domain.Inode, error)
	Unlink(ctx context.Context, parentIno int64, name string) error
	Rmdir(ctx context.Context, parentIno int64, name string) error
	Read(ctx context.Context, ino int64, offset, size int64) ([]byte, int64, error)
	Write(ctx context.Context, ino int64, offset int64, data []byte) (int64, int64, error)
	Link(ctx context.Context, ino int64, newParentIno int64, newName string) error
	GetTotalSize(ctx context.Context) (int64, error)
}

type filesystemService struct {
	repo *postgres.Repository
}

func NewFilesystemService(repo *postgres.Repository) FilesystemService {
	return &filesystemService{repo: repo}
}

func (s *filesystemService) Lookup(ctx context.Context, parentIno int64, name string) (*domain.Inode, error) {
	return s.repo.Lookup(ctx, parentIno, name)
}

func (s *filesystemService) List(ctx context.Context, parentIno int64) ([]domain.DirEntry, error) {
	return s.repo.List(ctx, parentIno)
}

func (s *filesystemService) Create(ctx context.Context, parentIno int64, name string, mode uint32) (*domain.Inode, error) {
	if name == "" || name == "." || name == ".." {
		return nil, domain.ErrInvalidName
	}
	return s.repo.Create(ctx, parentIno, name, mode)
}

func (s *filesystemService) Mkdir(ctx context.Context, parentIno int64, name string, mode uint32) (*domain.Inode, error) {
	if name == "" || name == "." || name == ".." {
		return nil, domain.ErrInvalidName
	}
	return s.repo.Mkdir(ctx, parentIno, name, mode)
}

func (s *filesystemService) Unlink(ctx context.Context, parentIno int64, name string) error {
	if name == "" || name == "." || name == ".." {
		return domain.ErrInvalidName
	}
	return s.repo.Unlink(ctx, parentIno, name)
}

func (s *filesystemService) Rmdir(ctx context.Context, parentIno int64, name string) error {
	if name == "" || name == "." || name == ".." {
		return domain.ErrInvalidName
	}
	return s.repo.Rmdir(ctx, parentIno, name)
}

func (s *filesystemService) Read(ctx context.Context, ino int64, offset, size int64) ([]byte, int64, error) {
	return s.repo.Read(ctx, ino, offset, size)
}

func (s *filesystemService) Write(ctx context.Context, ino int64, offset int64, data []byte) (int64, int64, error) {
	return s.repo.Write(ctx, ino, offset, data)
}

func (s *filesystemService) Link(ctx context.Context, ino int64, newParentIno int64, newName string) error {
	if newName == "" || newName == "." || newName == ".." {
		return domain.ErrInvalidName
	}
	return s.repo.Link(ctx, ino, newParentIno, newName)
}

func (s *filesystemService) GetTotalSize(ctx context.Context) (int64, error) {
	return s.repo.GetTotalSize(ctx)
}

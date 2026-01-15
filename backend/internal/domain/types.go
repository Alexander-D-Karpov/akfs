package domain

import (
	"time"
)

const (
	S_IFMT  uint32 = 0170000
	S_IFDIR uint32 = 0040000
	S_IFREG uint32 = 0100000
)

type Inode struct {
	Ino           uint64
	Mode          uint32
	Nlink         uint32
	Size          uint64
	Atime         time.Time
	Mtime         time.Time
	Ctime         time.Time
	FirstDataPage uint32
	NumDataPages  uint32
}

func (i *Inode) IsDir() bool {
	return (i.Mode & S_IFMT) == S_IFDIR
}

func (i *Inode) IsRegular() bool {
	return (i.Mode & S_IFMT) == S_IFREG
}

type DirEntry struct {
	Ino  uint64
	Mode uint32
	Name string
}

type Superblock struct {
	Magic        [8]byte
	Version      uint32
	PageSize     uint32
	TotalPages   uint64
	FreePages    uint64
	RootIno      uint32
	NextIno      uint64
	FreelistHead uint32
	MountCount   uint64
	State        uint32
}

const (
	StateClean   uint32 = 0
	StateMounted uint32 = 1
	StateError   uint32 = 2
)

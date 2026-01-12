package domain

import "time"

const (
	S_IFMT    = 0170000
	S_IFDIR   = 0040000
	S_IFREG   = 0100000
	S_IRWXU   = 00700
	S_IRWXG   = 00070
	S_IRWXO   = 00007
	S_IRWXUGO = S_IRWXU | S_IRWXG | S_IRWXO
)

type Inode struct {
	Ino       int64     `json:"ino"`
	Mode      uint32    `json:"mode"`
	Size      int64     `json:"size"`
	Nlink     int32     `json:"nlink"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (i *Inode) IsDir() bool {
	return (i.Mode & S_IFMT) == S_IFDIR
}

func (i *Inode) IsRegular() bool {
	return (i.Mode & S_IFMT) == S_IFREG
}

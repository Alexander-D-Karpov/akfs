package domain

import "errors"

var (
	ErrNotFound     = errors.New("no such file or directory")
	ErrExists       = errors.New("file exists")
	ErrNotEmpty     = errors.New("directory not empty")
	ErrNotDirectory = errors.New("not a directory")
	ErrIsDirectory  = errors.New("is a directory")
	ErrInvalidName  = errors.New("invalid name")
	ErrPermission   = errors.New("permission denied")
	ErrNoSpace      = errors.New("no space left on device")
)

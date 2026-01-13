package storage

import (
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/domain"
)

const (
	Magic          = "AKFSMAGC"
	Version        = 1
	PageSize       = 4096
	SuperblockPage = 0
	RootIno        = 1
	InodeSize      = 128
	InodesPerPage  = PageSize / InodeSize
	DirEntrySize   = 280
	MaxNameLen     = 255
	MaxFileSize    = 100 * 1024 * 1024

	InodeTableStart = 2
	InodeTablePages = 64
	DataPagesStart  = InodeTableStart + InodeTablePages
)

var (
	ErrNotFound    = errors.New("not found")
	ErrExists      = errors.New("already exists")
	ErrNotDir      = errors.New("not a directory")
	ErrIsDir       = errors.New("is a directory")
	ErrNotEmpty    = errors.New("directory not empty")
	ErrNoSpace     = errors.New("no space left")
	ErrInvalidName = errors.New("invalid name")
	ErrCorrupted   = errors.New("storage corrupted")
	ErrTooLarge    = errors.New("file too large")
)

type Storage struct {
	mu        sync.RWMutex
	file      *os.File
	path      string
	cache     *Cache
	wal       *WAL
	sb        domain.Superblock
	maxSize   int64
	inodes    map[uint64]*domain.Inode
	dirCache  map[uint64][]domain.DirEntry
	dataCache map[uint64][]byte
}

func NewStorage(path string, maxSize int64) (*Storage, error) {
	s := &Storage{
		path:      path,
		maxSize:   maxSize,
		inodes:    make(map[uint64]*domain.Inode),
		dirCache:  make(map[uint64][]domain.DirEntry),
		dataCache: make(map[uint64][]byte),
	}

	if err := s.open(); err != nil {
		return nil, err
	}

	s.cache = NewCache(1024)

	return s, nil
}

func (s *Storage) open() error {
	_, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return s.create()
	}
	if err != nil {
		return err
	}
	return s.load()
}

func (s *Storage) create() error {
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	s.file = f

	initialSize := int64(DataPagesStart+1024) * PageSize
	if err := f.Truncate(initialSize); err != nil {
		return err
	}

	s.sb = domain.Superblock{
		Version:      Version,
		PageSize:     PageSize,
		TotalPages:   uint64(initialSize / PageSize),
		FreePages:    uint64(initialSize/PageSize) - uint64(DataPagesStart),
		RootIno:      RootIno,
		NextIno:      2,
		FreelistHead: DataPagesStart,
		State:        domain.StateMounted,
	}
	copy(s.sb.Magic[:], Magic)

	if err := s.writeSuperblock(); err != nil {
		return err
	}

	now := time.Now()
	rootInode := &domain.Inode{
		Ino:   RootIno,
		Mode:  domain.S_IFDIR | 0777,
		Nlink: 2,
		Size:  0,
		Atime: now,
		Mtime: now,
		Ctime: now,
	}
	s.inodes[RootIno] = rootInode
	s.dirCache[RootIno] = []domain.DirEntry{}

	return s.flush()
}

func (s *Storage) load() error {
	f, err := os.OpenFile(s.path, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	s.file = f

	if err := s.readSuperblock(); err != nil {
		return err
	}

	if string(s.sb.Magic[:]) != Magic {
		return ErrCorrupted
	}

	if err := s.loadInodes(); err != nil {
		return err
	}

	s.sb.State = domain.StateMounted
	s.sb.MountCount++
	return s.writeSuperblock()
}

func (s *Storage) writeSuperblock() error {
	buf := make([]byte, PageSize)
	copy(buf[0:8], s.sb.Magic[:])
	binary.LittleEndian.PutUint32(buf[8:12], s.sb.Version)
	binary.LittleEndian.PutUint32(buf[12:16], s.sb.PageSize)
	binary.LittleEndian.PutUint64(buf[16:24], s.sb.TotalPages)
	binary.LittleEndian.PutUint64(buf[24:32], s.sb.FreePages)
	binary.LittleEndian.PutUint32(buf[32:36], s.sb.RootIno)
	binary.LittleEndian.PutUint64(buf[36:44], s.sb.NextIno)
	binary.LittleEndian.PutUint32(buf[44:48], s.sb.FreelistHead)
	binary.LittleEndian.PutUint64(buf[48:56], s.sb.MountCount)
	binary.LittleEndian.PutUint32(buf[56:60], s.sb.State)

	_, err := s.file.WriteAt(buf, 0)
	return err
}

func (s *Storage) readSuperblock() error {
	buf := make([]byte, PageSize)
	_, err := s.file.ReadAt(buf, 0)
	if err != nil {
		return err
	}

	copy(s.sb.Magic[:], buf[0:8])
	s.sb.Version = binary.LittleEndian.Uint32(buf[8:12])
	s.sb.PageSize = binary.LittleEndian.Uint32(buf[12:16])
	s.sb.TotalPages = binary.LittleEndian.Uint64(buf[16:24])
	s.sb.FreePages = binary.LittleEndian.Uint64(buf[24:32])
	s.sb.RootIno = binary.LittleEndian.Uint32(buf[32:36])
	s.sb.NextIno = binary.LittleEndian.Uint64(buf[36:44])
	s.sb.FreelistHead = binary.LittleEndian.Uint32(buf[44:48])
	s.sb.MountCount = binary.LittleEndian.Uint64(buf[48:56])
	s.sb.State = binary.LittleEndian.Uint32(buf[56:60])

	return nil
}

func (s *Storage) loadInodes() error {
	buf := make([]byte, PageSize)

	for page := uint32(InodeTableStart); page < InodeTableStart+InodeTablePages; page++ {
		offset := int64(page) * PageSize
		n, err := s.file.ReadAt(buf, offset)
		if err != nil || n != PageSize {
			continue
		}

		for i := 0; i < InodesPerPage; i++ {
			inodeBuf := buf[i*InodeSize : (i+1)*InodeSize]
			ino := binary.LittleEndian.Uint64(inodeBuf[0:8])
			if ino == 0 {
				continue
			}

			inode := &domain.Inode{
				Ino:   ino,
				Mode:  binary.LittleEndian.Uint32(inodeBuf[8:12]),
				Nlink: binary.LittleEndian.Uint32(inodeBuf[12:16]),
				Size:  binary.LittleEndian.Uint64(inodeBuf[16:24]),
			}
			inode.Atime = time.Unix(int64(binary.LittleEndian.Uint64(inodeBuf[24:32])), 0)
			inode.Mtime = time.Unix(int64(binary.LittleEndian.Uint64(inodeBuf[32:40])), 0)
			inode.Ctime = time.Unix(int64(binary.LittleEndian.Uint64(inodeBuf[40:48])), 0)

			numPages := binary.LittleEndian.Uint32(inodeBuf[48:52])
			inode.DataPages = make([]uint32, numPages)
			for j := uint32(0); j < numPages && j < 16; j++ {
				inode.DataPages[j] = binary.LittleEndian.Uint32(inodeBuf[52+j*4 : 56+j*4])
			}

			s.inodes[ino] = inode

			if inode.IsDir() {
				entries, err := s.loadDirEntries(inode)
				if err == nil {
					s.dirCache[ino] = entries
				} else {
					s.dirCache[ino] = []domain.DirEntry{}
				}
			} else if inode.Size > 0 {
				data, err := s.loadFileData(inode)
				if err == nil {
					s.dataCache[ino] = data
				}
			}
		}
	}

	if _, ok := s.inodes[RootIno]; !ok {
		now := time.Now()
		s.inodes[RootIno] = &domain.Inode{
			Ino:   RootIno,
			Mode:  domain.S_IFDIR | 0777,
			Nlink: 2,
			Size:  0,
			Atime: now,
			Mtime: now,
			Ctime: now,
		}
		s.dirCache[RootIno] = []domain.DirEntry{}
	}

	return nil
}

func (s *Storage) loadDirEntries(inode *domain.Inode) ([]domain.DirEntry, error) {
	var entries []domain.DirEntry

	for _, pageNum := range inode.DataPages {
		if pageNum == 0 {
			continue
		}

		buf := make([]byte, PageSize)
		offset := int64(pageNum) * PageSize
		_, err := s.file.ReadAt(buf, offset)
		if err != nil {
			continue
		}

		numEntries := binary.LittleEndian.Uint32(buf[0:4])
		off := 4
		for i := uint32(0); i < numEntries; i++ {
			if off+DirEntrySize > PageSize {
				break
			}
			ino := binary.LittleEndian.Uint64(buf[off : off+8])
			mode := binary.LittleEndian.Uint32(buf[off+8 : off+12])
			nameLen := binary.LittleEndian.Uint16(buf[off+12 : off+14])
			name := string(buf[off+14 : off+14+int(nameLen)])

			if ino != 0 {
				entries = append(entries, domain.DirEntry{
					Ino:  ino,
					Mode: mode,
					Name: name,
				})
			}
			off += DirEntrySize
		}
	}

	return entries, nil
}

func (s *Storage) loadFileData(inode *domain.Inode) ([]byte, error) {
	data := make([]byte, 0, inode.Size)

	for _, pageNum := range inode.DataPages {
		if pageNum == 0 {
			continue
		}

		buf := make([]byte, PageSize)
		offset := int64(pageNum) * PageSize
		_, err := s.file.ReadAt(buf, offset)
		if err != nil {
			continue
		}

		dataLen := binary.LittleEndian.Uint32(buf[0:4])
		if dataLen > PageSize-4 {
			dataLen = PageSize - 4
		}
		data = append(data, buf[4:4+dataLen]...)
	}

	if uint64(len(data)) > inode.Size {
		data = data[:inode.Size]
	}

	return data, nil
}

func (s *Storage) flush() error {
	for ino, inode := range s.inodes {
		if err := s.writeInode(inode); err != nil {
			return err
		}

		if inode.IsDir() {
			if entries, ok := s.dirCache[ino]; ok {
				if err := s.writeDirEntries(inode, entries); err != nil {
					return err
				}
			}
		} else {
			if data, ok := s.dataCache[ino]; ok {
				if err := s.writeFileData(inode, data); err != nil {
					return err
				}
			}
		}
	}

	return s.writeSuperblock()
}

func (s *Storage) writeInode(inode *domain.Inode) error {
	pageNum := InodeTableStart + uint32((inode.Ino-1)/uint64(InodesPerPage))
	indexInPage := int((inode.Ino - 1) % uint64(InodesPerPage))

	buf := make([]byte, PageSize)
	offset := int64(pageNum) * PageSize
	s.file.ReadAt(buf, offset)

	inodeBuf := buf[indexInPage*InodeSize : (indexInPage+1)*InodeSize]
	binary.LittleEndian.PutUint64(inodeBuf[0:8], inode.Ino)
	binary.LittleEndian.PutUint32(inodeBuf[8:12], inode.Mode)
	binary.LittleEndian.PutUint32(inodeBuf[12:16], inode.Nlink)
	binary.LittleEndian.PutUint64(inodeBuf[16:24], inode.Size)
	binary.LittleEndian.PutUint64(inodeBuf[24:32], uint64(inode.Atime.Unix()))
	binary.LittleEndian.PutUint64(inodeBuf[32:40], uint64(inode.Mtime.Unix()))
	binary.LittleEndian.PutUint64(inodeBuf[40:48], uint64(inode.Ctime.Unix()))

	numPages := uint32(len(inode.DataPages))
	binary.LittleEndian.PutUint32(inodeBuf[48:52], numPages)
	for j := uint32(0); j < numPages && j < 16; j++ {
		binary.LittleEndian.PutUint32(inodeBuf[52+j*4:56+j*4], inode.DataPages[j])
	}

	_, err := s.file.WriteAt(buf, offset)
	return err
}

func (s *Storage) writeDirEntries(inode *domain.Inode, entries []domain.DirEntry) error {
	if len(inode.DataPages) == 0 {
		page, err := s.allocPage()
		if err != nil {
			return err
		}
		inode.DataPages = []uint32{page}
	}

	pageNum := inode.DataPages[0]
	buf := make([]byte, PageSize)
	binary.LittleEndian.PutUint32(buf[0:4], uint32(len(entries)))

	off := 4
	for _, entry := range entries {
		if off+DirEntrySize > PageSize {
			break
		}
		binary.LittleEndian.PutUint64(buf[off:off+8], entry.Ino)
		binary.LittleEndian.PutUint32(buf[off+8:off+12], entry.Mode)
		nameBytes := []byte(entry.Name)
		if len(nameBytes) > MaxNameLen {
			nameBytes = nameBytes[:MaxNameLen]
		}
		binary.LittleEndian.PutUint16(buf[off+12:off+14], uint16(len(nameBytes)))
		copy(buf[off+14:], nameBytes)
		off += DirEntrySize
	}

	offset := int64(pageNum) * PageSize
	_, err := s.file.WriteAt(buf, offset)
	return err
}

func (s *Storage) writeFileData(inode *domain.Inode, data []byte) error {
	neededPages := (len(data) + PageSize - 5) / (PageSize - 4)
	if neededPages == 0 {
		neededPages = 1
	}

	for len(inode.DataPages) < neededPages {
		page, err := s.allocPage()
		if err != nil {
			return err
		}
		inode.DataPages = append(inode.DataPages, page)
	}

	offset := 0
	for i := 0; i < neededPages; i++ {
		pageNum := inode.DataPages[i]
		buf := make([]byte, PageSize)

		remaining := len(data) - offset
		chunkSize := PageSize - 4
		if remaining < chunkSize {
			chunkSize = remaining
		}

		binary.LittleEndian.PutUint32(buf[0:4], uint32(chunkSize))
		if chunkSize > 0 {
			copy(buf[4:], data[offset:offset+chunkSize])
		}

		pageOffset := int64(pageNum) * PageSize
		if _, err := s.file.WriteAt(buf, pageOffset); err != nil {
			return err
		}

		offset += chunkSize
	}

	return nil
}

func (s *Storage) allocPage() (uint32, error) {
	if s.sb.FreePages == 0 {
		if err := s.growFile(); err != nil {
			return 0, err
		}
	}

	page := s.sb.FreelistHead
	s.sb.FreelistHead++
	s.sb.FreePages--

	return page, nil
}

func (s *Storage) growFile() error {
	newPages := uint64(1024)
	newSize := int64(s.sb.TotalPages+newPages) * PageSize

	if newSize > s.maxSize {
		return ErrNoSpace
	}

	if err := s.file.Truncate(newSize); err != nil {
		return err
	}

	s.sb.TotalPages += newPages
	s.sb.FreePages += newPages

	return nil
}

func (s *Storage) Lookup(parentIno uint64, name string) (*domain.Inode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, ok := s.dirCache[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	for _, entry := range entries {
		if entry.Name == name {
			inode, ok := s.inodes[entry.Ino]
			if !ok {
				return nil, ErrNotFound
			}
			return inode, nil
		}
	}

	return nil, ErrNotFound
}

func (s *Storage) GetInode(ino uint64) (*domain.Inode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inode, ok := s.inodes[ino]
	if !ok {
		return nil, ErrNotFound
	}
	return inode, nil
}

func (s *Storage) List(parentIno uint64) ([]domain.DirEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	parent, ok := s.inodes[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	if !parent.IsDir() {
		return nil, ErrNotDir
	}

	entries, ok := s.dirCache[parentIno]
	if !ok {
		return []domain.DirEntry{}, nil
	}

	result := make([]domain.DirEntry, len(entries))
	copy(result, entries)
	return result, nil
}

func (s *Storage) Create(parentIno uint64, name string, mode uint32) (*domain.Inode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." || len(name) > MaxNameLen {
		return nil, ErrInvalidName
	}

	parent, ok := s.inodes[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	if !parent.IsDir() {
		return nil, ErrNotDir
	}

	entries := s.dirCache[parentIno]
	for _, entry := range entries {
		if entry.Name == name {
			return nil, ErrExists
		}
	}

	now := time.Now()
	ino := s.sb.NextIno
	s.sb.NextIno++

	inode := &domain.Inode{
		Ino:   ino,
		Mode:  domain.S_IFREG | (mode & 0777),
		Nlink: 1,
		Size:  0,
		Atime: now,
		Mtime: now,
		Ctime: now,
	}

	s.inodes[ino] = inode
	s.dataCache[ino] = []byte{}
	s.dirCache[parentIno] = append(entries, domain.DirEntry{
		Ino:  ino,
		Mode: inode.Mode,
		Name: name,
	})

	parent.Mtime = now
	parent.Ctime = now

	s.flush()
	return inode, nil
}

func (s *Storage) Mkdir(parentIno uint64, name string, mode uint32) (*domain.Inode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." || len(name) > MaxNameLen {
		return nil, ErrInvalidName
	}

	parent, ok := s.inodes[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	if !parent.IsDir() {
		return nil, ErrNotDir
	}

	entries := s.dirCache[parentIno]
	for _, entry := range entries {
		if entry.Name == name {
			return nil, ErrExists
		}
	}

	now := time.Now()
	ino := s.sb.NextIno
	s.sb.NextIno++

	inode := &domain.Inode{
		Ino:   ino,
		Mode:  domain.S_IFDIR | (mode & 0777),
		Nlink: 2,
		Size:  0,
		Atime: now,
		Mtime: now,
		Ctime: now,
	}

	s.inodes[ino] = inode
	s.dirCache[ino] = []domain.DirEntry{}
	s.dirCache[parentIno] = append(entries, domain.DirEntry{
		Ino:  ino,
		Mode: inode.Mode,
		Name: name,
	})

	parent.Nlink++
	parent.Mtime = now
	parent.Ctime = now

	s.flush()
	return inode, nil
}

func (s *Storage) Unlink(parentIno uint64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." {
		return ErrInvalidName
	}

	parent, ok := s.inodes[parentIno]
	if !ok {
		return ErrNotFound
	}

	entries := s.dirCache[parentIno]
	idx := -1
	var targetIno uint64
	for i, entry := range entries {
		if entry.Name == name {
			idx = i
			targetIno = entry.Ino
			break
		}
	}

	if idx == -1 {
		return ErrNotFound
	}

	target, ok := s.inodes[targetIno]
	if !ok {
		return ErrNotFound
	}

	if target.IsDir() {
		return ErrIsDir
	}

	target.Nlink--
	if target.Nlink == 0 {
		delete(s.inodes, targetIno)
		delete(s.dataCache, targetIno)
	}

	s.dirCache[parentIno] = append(entries[:idx], entries[idx+1:]...)

	now := time.Now()
	parent.Mtime = now
	parent.Ctime = now

	s.flush()
	return nil
}

func (s *Storage) Rmdir(parentIno uint64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." {
		return ErrInvalidName
	}

	parent, ok := s.inodes[parentIno]
	if !ok {
		return ErrNotFound
	}

	entries := s.dirCache[parentIno]
	idx := -1
	var targetIno uint64
	for i, entry := range entries {
		if entry.Name == name {
			idx = i
			targetIno = entry.Ino
			break
		}
	}

	if idx == -1 {
		return ErrNotFound
	}

	target, ok := s.inodes[targetIno]
	if !ok {
		return ErrNotFound
	}

	if !target.IsDir() {
		return ErrNotDir
	}

	targetEntries := s.dirCache[targetIno]
	if len(targetEntries) > 0 {
		return ErrNotEmpty
	}

	delete(s.inodes, targetIno)
	delete(s.dirCache, targetIno)

	s.dirCache[parentIno] = append(entries[:idx], entries[idx+1:]...)

	parent.Nlink--
	now := time.Now()
	parent.Mtime = now
	parent.Ctime = now

	s.flush()
	return nil
}

func (s *Storage) Link(ino uint64, newParentIno uint64, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if newName == "" || newName == "." || newName == ".." || len(newName) > MaxNameLen {
		return ErrInvalidName
	}

	target, ok := s.inodes[ino]
	if !ok {
		return ErrNotFound
	}

	if target.IsDir() {
		return ErrIsDir
	}

	newParent, ok := s.inodes[newParentIno]
	if !ok {
		return ErrNotFound
	}

	if !newParent.IsDir() {
		return ErrNotDir
	}

	entries := s.dirCache[newParentIno]
	for _, entry := range entries {
		if entry.Name == newName {
			return ErrExists
		}
	}

	target.Nlink++
	s.dirCache[newParentIno] = append(entries, domain.DirEntry{
		Ino:  ino,
		Mode: target.Mode,
		Name: newName,
	})

	now := time.Now()
	newParent.Mtime = now
	newParent.Ctime = now
	target.Ctime = now

	s.flush()
	return nil
}

func (s *Storage) Read(ino uint64, offset int64, size int64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inode, ok := s.inodes[ino]
	if !ok {
		return nil, ErrNotFound
	}

	if inode.IsDir() {
		return nil, ErrIsDir
	}

	data, ok := s.dataCache[ino]
	if !ok {
		data = []byte{}
	}

	if offset >= int64(len(data)) {
		return []byte{}, nil
	}

	end := offset + size
	if end > int64(len(data)) {
		end = int64(len(data))
	}

	result := make([]byte, end-offset)
	copy(result, data[offset:end])
	return result, nil
}

func (s *Storage) Write(ino uint64, offset int64, data []byte) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	inode, ok := s.inodes[ino]
	if !ok {
		return 0, 0, ErrNotFound
	}

	if inode.IsDir() {
		return 0, 0, ErrIsDir
	}

	newSize := offset + int64(len(data))
	if newSize > MaxFileSize {
		return 0, 0, ErrTooLarge
	}

	existing, ok := s.dataCache[ino]
	if !ok {
		existing = []byte{}
	}

	if int64(len(existing)) < newSize {
		newData := make([]byte, newSize)
		copy(newData, existing)
		existing = newData
	}

	copy(existing[offset:], data)
	s.dataCache[ino] = existing

	inode.Size = uint64(len(existing))
	now := time.Now()
	inode.Mtime = now
	inode.Ctime = now

	s.flush()
	return int64(len(data)), int64(inode.Size), nil
}

func (s *Storage) GetTotalSize() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	for _, inode := range s.inodes {
		if !inode.IsDir() {
			total += int64(inode.Size)
		}
	}
	return total
}

func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sb.State = domain.StateClean
	s.writeSuperblock()

	return s.file.Close()
}

func (s *Storage) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.flush(); err != nil {
		return err
	}
	return s.file.Sync()
}

func (s *Storage) Truncate(ino uint64, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inode, ok := s.inodes[ino]
	if !ok {
		return ErrNotFound
	}

	if inode.IsDir() {
		return ErrIsDir
	}

	data, ok := s.dataCache[ino]
	if !ok {
		data = []byte{}
	}

	if int64(len(data)) > size {
		data = data[:size]
	} else if int64(len(data)) < size {
		newData := make([]byte, size)
		copy(newData, data)
		data = newData
	}

	s.dataCache[ino] = data
	inode.Size = uint64(size)
	now := time.Now()
	inode.Mtime = now
	inode.Ctime = now

	s.flush()
	return nil
}

func (s *Storage) Rename(oldParentIno uint64, oldName string, newParentIno uint64, newName string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if oldName == "" || oldName == "." || oldName == ".." || len(oldName) > MaxNameLen {
		return 0, ErrInvalidName
	}
	if newName == "" || newName == "." || newName == ".." || len(newName) > MaxNameLen {
		return 0, ErrInvalidName
	}

	oldParent, ok := s.inodes[oldParentIno]
	if !ok {
		return 0, ErrNotFound
	}
	if !oldParent.IsDir() {
		return 0, ErrNotDir
	}

	newParent, ok := s.inodes[newParentIno]
	if !ok {
		return 0, ErrNotFound
	}
	if !newParent.IsDir() {
		return 0, ErrNotDir
	}

	oldEntries, ok := s.dirCache[oldParentIno]
	if !ok {
		return 0, ErrNotFound
	}

	srcIdx := -1
	var srcIno uint64
	var srcMode uint32
	for i, e := range oldEntries {
		if e.Name == oldName {
			srcIdx = i
			srcIno = e.Ino
			srcMode = e.Mode
			break
		}
	}
	if srcIdx == -1 {
		return 0, ErrNotFound
	}

	srcInode, ok := s.inodes[srcIno]
	if !ok {
		return 0, ErrNotFound
	}

	if oldParentIno == newParentIno && oldName == newName {
		return srcIno, nil
	}

	newEntries := s.dirCache[newParentIno]
	dstIdx := -1
	var dstIno uint64
	for i, e := range newEntries {
		if e.Name == newName {
			dstIdx = i
			dstIno = e.Ino
			break
		}
	}

	if dstIdx != -1 {
		dstInode, ok := s.inodes[dstIno]
		if !ok {
			return 0, ErrNotFound
		}

		if srcInode.IsDir() && !dstInode.IsDir() {
			return 0, ErrNotDir
		}
		if !srcInode.IsDir() && dstInode.IsDir() {
			return 0, ErrIsDir
		}

		if dstInode.IsDir() {
			dstEntries := s.dirCache[dstIno]
			if len(dstEntries) > 0 {
				return 0, ErrNotEmpty
			}
			delete(s.inodes, dstIno)
			delete(s.dirCache, dstIno)

			newEntries = append(newEntries[:dstIdx], newEntries[dstIdx+1:]...)
			s.dirCache[newParentIno] = newEntries

			if newParent.Nlink > 0 {
				newParent.Nlink--
			}
		} else {
			dstInode.Nlink--
			if dstInode.Nlink == 0 {
				delete(s.inodes, dstIno)
				delete(s.dataCache, dstIno)
			}
			newEntries = append(newEntries[:dstIdx], newEntries[dstIdx+1:]...)
			s.dirCache[newParentIno] = newEntries
		}
	}

	oldEntries = append(oldEntries[:srcIdx], oldEntries[srcIdx+1:]...)
	s.dirCache[oldParentIno] = oldEntries

	entry := domain.DirEntry{
		Ino:  srcIno,
		Mode: srcMode,
		Name: newName,
	}
	s.dirCache[newParentIno] = append(s.dirCache[newParentIno], entry)

	now := time.Now()

	if srcInode.IsDir() && oldParentIno != newParentIno {
		if oldParent.Nlink > 0 {
			oldParent.Nlink--
		}
		newParent.Nlink++
	}

	oldParent.Mtime, oldParent.Ctime = now, now
	newParent.Mtime, newParent.Ctime = now, now
	srcInode.Ctime = now

	if err := s.flush(); err != nil {
		return 0, err
	}

	return srcIno, nil
}

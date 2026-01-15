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
	MaxFileSize    = 2 * 1024 * 1024 * 1024

	InodeTableStart = 2
	InodeTablePages = 256
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

type InodeData struct {
	inode      *domain.Inode
	data       []byte
	dirEntries []domain.DirEntry
	dirty      bool
}

type Storage struct {
	mu        sync.RWMutex
	file      *os.File
	path      string
	cache     *Cache
	wal       *WAL
	sb        domain.Superblock
	maxSize   int64
	inodeData map[uint64]*InodeData
	freePages []uint32
}

func NewStorage(path string, maxSize int64) (*Storage, error) {
	s := &Storage{
		path:      path,
		maxSize:   maxSize,
		inodeData: make(map[uint64]*InodeData),
		freePages: make([]uint32, 0),
	}

	if err := s.open(); err != nil {
		return nil, err
	}

	s.cache = NewCache(4096)

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

	initialSize := int64(DataPagesStart+4096) * PageSize
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

	s.inodeData[RootIno] = &InodeData{
		inode:      rootInode,
		dirEntries: []domain.DirEntry{},
		dirty:      true,
	}

	return s.syncInode(RootIno)
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

	if _, err := s.file.WriteAt(buf, 0); err != nil {
		return err
	}
	if _, err := s.file.WriteAt(buf, PageSize); err != nil {
		return err
	}
	return nil
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

			numDataPages := binary.LittleEndian.Uint32(inodeBuf[48:52])
			firstDataPage := binary.LittleEndian.Uint32(inodeBuf[52:56])

			inodeData := &InodeData{
				inode: inode,
				dirty: false,
			}

			if inode.IsDir() {
				if firstDataPage != 0 {
					entries, err := s.loadDirEntriesFromPage(firstDataPage)
					if err == nil {
						inodeData.dirEntries = entries
					} else {
						inodeData.dirEntries = []domain.DirEntry{}
					}
				} else {
					inodeData.dirEntries = []domain.DirEntry{}
				}
			} else if inode.Size > 0 && numDataPages > 0 && firstDataPage != 0 {
				data, err := s.loadFileDataFromPages(firstDataPage, numDataPages, inode.Size)
				if err == nil {
					inodeData.data = data
				}
			}

			s.inodeData[ino] = inodeData
		}
	}

	if _, ok := s.inodeData[RootIno]; !ok {
		now := time.Now()
		s.inodeData[RootIno] = &InodeData{
			inode: &domain.Inode{
				Ino:   RootIno,
				Mode:  domain.S_IFDIR | 0777,
				Nlink: 2,
				Size:  0,
				Atime: now,
				Mtime: now,
				Ctime: now,
			},
			dirEntries: []domain.DirEntry{},
			dirty:      true,
		}
	}

	return nil
}

func (s *Storage) loadDirEntriesFromPage(pageNum uint32) ([]domain.DirEntry, error) {
	var entries []domain.DirEntry

	buf := make([]byte, PageSize)
	offset := int64(pageNum) * PageSize
	_, err := s.file.ReadAt(buf, offset)
	if err != nil {
		return entries, err
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

	return entries, nil
}

func (s *Storage) loadFileDataFromPages(firstPage uint32, numPages uint32, size uint64) ([]byte, error) {
	data := make([]byte, 0, size)
	dataPerPage := PageSize - 8

	currentPage := firstPage
	for i := uint32(0); i < numPages && currentPage != 0; i++ {
		buf := make([]byte, PageSize)
		offset := int64(currentPage) * PageSize
		_, err := s.file.ReadAt(buf, offset)
		if err != nil {
			break
		}

		nextPage := binary.LittleEndian.Uint32(buf[0:4])
		chunkLen := binary.LittleEndian.Uint32(buf[4:8])

		if chunkLen > uint32(dataPerPage) {
			chunkLen = uint32(dataPerPage)
		}

		data = append(data, buf[8:8+chunkLen]...)
		currentPage = nextPage
	}

	if uint64(len(data)) > size {
		data = data[:size]
	}

	return data, nil
}

func (s *Storage) syncInode(ino uint64) error {
	inodeData, ok := s.inodeData[ino]
	if !ok {
		return ErrNotFound
	}

	if !inodeData.dirty {
		return nil
	}

	if inodeData.inode.IsDir() {
		if err := s.writeDirEntriesToDisk(inodeData); err != nil {
			return err
		}
	} else if len(inodeData.data) > 0 {
		if err := s.writeFileDataToDisk(inodeData); err != nil {
			return err
		}
	}

	if err := s.writeInodeToDisk(inodeData.inode); err != nil {
		return err
	}

	inodeData.dirty = false
	return nil
}

func (s *Storage) writeInodeToDisk(inode *domain.Inode) error {
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
	binary.LittleEndian.PutUint32(inodeBuf[48:52], inode.NumDataPages)
	binary.LittleEndian.PutUint32(inodeBuf[52:56], inode.FirstDataPage)

	_, err := s.file.WriteAt(buf, offset)
	return err
}

func (s *Storage) writeDirEntriesToDisk(inodeData *InodeData) error {
	inode := inodeData.inode
	entries := inodeData.dirEntries

	if inode.FirstDataPage == 0 && len(entries) > 0 {
		page, err := s.allocPage()
		if err != nil {
			return err
		}
		inode.FirstDataPage = page
		inode.NumDataPages = 1
	}

	if inode.FirstDataPage == 0 {
		return nil
	}

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

	pageOffset := int64(inode.FirstDataPage) * PageSize
	_, err := s.file.WriteAt(buf, pageOffset)
	return err
}

func (s *Storage) writeFileDataToDisk(inodeData *InodeData) error {
	inode := inodeData.inode
	data := inodeData.data

	if len(data) == 0 {
		return nil
	}

	dataPerPage := PageSize - 8
	neededPages := (len(data) + dataPerPage - 1) / dataPerPage

	var pages []uint32

	if inode.FirstDataPage != 0 {
		currentPage := inode.FirstDataPage
		for currentPage != 0 && len(pages) < neededPages {
			pages = append(pages, currentPage)

			buf := make([]byte, 4)
			s.file.ReadAt(buf, int64(currentPage)*PageSize)
			currentPage = binary.LittleEndian.Uint32(buf)
		}
	}

	for len(pages) < neededPages {
		page, err := s.allocPage()
		if err != nil {
			return err
		}
		pages = append(pages, page)
	}

	if len(pages) > 0 {
		inode.FirstDataPage = pages[0]
	}
	inode.NumDataPages = uint32(len(pages))

	offset := 0
	for i, pageNum := range pages {
		buf := make([]byte, PageSize)

		var nextPage uint32 = 0
		if i+1 < len(pages) {
			nextPage = pages[i+1]
		}
		binary.LittleEndian.PutUint32(buf[0:4], nextPage)

		remaining := len(data) - offset
		chunkSize := dataPerPage
		if remaining < chunkSize {
			chunkSize = remaining
		}

		binary.LittleEndian.PutUint32(buf[4:8], uint32(chunkSize))
		if chunkSize > 0 {
			copy(buf[8:8+chunkSize], data[offset:offset+chunkSize])
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
	if len(s.freePages) > 0 {
		page := s.freePages[len(s.freePages)-1]
		s.freePages = s.freePages[:len(s.freePages)-1]
		return page, nil
	}

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
	newPages := uint64(4096)
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

	inodeData, ok := s.inodeData[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	for _, entry := range inodeData.dirEntries {
		if entry.Name == name {
			targetData, ok := s.inodeData[entry.Ino]
			if !ok {
				return nil, ErrNotFound
			}
			return targetData.inode, nil
		}
	}

	return nil, ErrNotFound
}

func (s *Storage) GetInode(ino uint64) (*domain.Inode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inodeData, ok := s.inodeData[ino]
	if !ok {
		return nil, ErrNotFound
	}
	return inodeData.inode, nil
}

func (s *Storage) List(parentIno uint64) ([]domain.DirEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inodeData, ok := s.inodeData[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	if !inodeData.inode.IsDir() {
		return nil, ErrNotDir
	}

	result := make([]domain.DirEntry, len(inodeData.dirEntries))
	copy(result, inodeData.dirEntries)
	return result, nil
}

func (s *Storage) Create(parentIno uint64, name string, mode uint32) (*domain.Inode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." || len(name) > MaxNameLen {
		return nil, ErrInvalidName
	}

	parentData, ok := s.inodeData[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	if !parentData.inode.IsDir() {
		return nil, ErrNotDir
	}

	for _, entry := range parentData.dirEntries {
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

	s.inodeData[ino] = &InodeData{
		inode: inode,
		data:  []byte{},
		dirty: true,
	}

	parentData.dirEntries = append(parentData.dirEntries, domain.DirEntry{
		Ino:  ino,
		Mode: inode.Mode,
		Name: name,
	})
	parentData.inode.Mtime = now
	parentData.inode.Ctime = now
	parentData.dirty = true

	s.syncInode(ino)
	s.syncInode(parentIno)
	s.writeSuperblock()

	return inode, nil
}

func (s *Storage) Mkdir(parentIno uint64, name string, mode uint32) (*domain.Inode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." || len(name) > MaxNameLen {
		return nil, ErrInvalidName
	}

	parentData, ok := s.inodeData[parentIno]
	if !ok {
		return nil, ErrNotFound
	}

	if !parentData.inode.IsDir() {
		return nil, ErrNotDir
	}

	for _, entry := range parentData.dirEntries {
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

	s.inodeData[ino] = &InodeData{
		inode:      inode,
		dirEntries: []domain.DirEntry{},
		dirty:      true,
	}

	parentData.dirEntries = append(parentData.dirEntries, domain.DirEntry{
		Ino:  ino,
		Mode: inode.Mode,
		Name: name,
	})
	parentData.inode.Nlink++
	parentData.inode.Mtime = now
	parentData.inode.Ctime = now
	parentData.dirty = true

	s.syncInode(ino)
	s.syncInode(parentIno)
	s.writeSuperblock()

	return inode, nil
}

func (s *Storage) Unlink(parentIno uint64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." {
		return ErrInvalidName
	}

	parentData, ok := s.inodeData[parentIno]
	if !ok {
		return ErrNotFound
	}

	idx := -1
	var targetIno uint64
	for i, entry := range parentData.dirEntries {
		if entry.Name == name {
			idx = i
			targetIno = entry.Ino
			break
		}
	}

	if idx == -1 {
		return ErrNotFound
	}

	targetData, ok := s.inodeData[targetIno]
	if !ok {
		return ErrNotFound
	}

	if targetData.inode.IsDir() {
		return ErrIsDir
	}

	targetData.inode.Nlink--
	if targetData.inode.Nlink == 0 {
		delete(s.inodeData, targetIno)
	} else {
		targetData.dirty = true
		s.syncInode(targetIno)
	}

	parentData.dirEntries = append(parentData.dirEntries[:idx], parentData.dirEntries[idx+1:]...)
	now := time.Now()
	parentData.inode.Mtime = now
	parentData.inode.Ctime = now
	parentData.dirty = true

	s.syncInode(parentIno)
	return nil
}

func (s *Storage) Rmdir(parentIno uint64, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if name == "" || name == "." || name == ".." {
		return ErrInvalidName
	}

	parentData, ok := s.inodeData[parentIno]
	if !ok {
		return ErrNotFound
	}

	idx := -1
	var targetIno uint64
	for i, entry := range parentData.dirEntries {
		if entry.Name == name {
			idx = i
			targetIno = entry.Ino
			break
		}
	}

	if idx == -1 {
		return ErrNotFound
	}

	targetData, ok := s.inodeData[targetIno]
	if !ok {
		return ErrNotFound
	}

	if !targetData.inode.IsDir() {
		return ErrNotDir
	}

	if len(targetData.dirEntries) > 0 {
		return ErrNotEmpty
	}

	delete(s.inodeData, targetIno)

	parentData.dirEntries = append(parentData.dirEntries[:idx], parentData.dirEntries[idx+1:]...)
	parentData.inode.Nlink--
	now := time.Now()
	parentData.inode.Mtime = now
	parentData.inode.Ctime = now
	parentData.dirty = true

	s.syncInode(parentIno)
	return nil
}

func (s *Storage) Link(ino uint64, newParentIno uint64, newName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if newName == "" || newName == "." || newName == ".." || len(newName) > MaxNameLen {
		return ErrInvalidName
	}

	targetData, ok := s.inodeData[ino]
	if !ok {
		return ErrNotFound
	}

	if targetData.inode.IsDir() {
		return ErrIsDir
	}

	newParentData, ok := s.inodeData[newParentIno]
	if !ok {
		return ErrNotFound
	}

	if !newParentData.inode.IsDir() {
		return ErrNotDir
	}

	for _, entry := range newParentData.dirEntries {
		if entry.Name == newName {
			return ErrExists
		}
	}

	targetData.inode.Nlink++
	targetData.dirty = true

	newParentData.dirEntries = append(newParentData.dirEntries, domain.DirEntry{
		Ino:  ino,
		Mode: targetData.inode.Mode,
		Name: newName,
	})

	now := time.Now()
	newParentData.inode.Mtime = now
	newParentData.inode.Ctime = now
	targetData.inode.Ctime = now
	newParentData.dirty = true

	s.syncInode(ino)
	s.syncInode(newParentIno)
	return nil
}

func (s *Storage) Read(ino uint64, offset int64, size int64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inodeData, ok := s.inodeData[ino]
	if !ok {
		return nil, ErrNotFound
	}

	if inodeData.inode.IsDir() {
		return nil, ErrIsDir
	}

	data := inodeData.data
	if data == nil {
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

	inodeData, ok := s.inodeData[ino]
	if !ok {
		return 0, 0, ErrNotFound
	}

	if inodeData.inode.IsDir() {
		return 0, 0, ErrIsDir
	}

	newSize := offset + int64(len(data))
	if newSize > MaxFileSize {
		return 0, 0, ErrTooLarge
	}

	existing := inodeData.data
	if existing == nil {
		existing = []byte{}
	}

	if int64(len(existing)) < newSize {
		newData := make([]byte, newSize)
		copy(newData, existing)
		existing = newData
	}

	copy(existing[offset:], data)
	inodeData.data = existing

	inodeData.inode.Size = uint64(len(existing))
	now := time.Now()
	inodeData.inode.Mtime = now
	inodeData.inode.Ctime = now
	inodeData.dirty = true

	s.syncInode(ino)

	return int64(len(data)), int64(inodeData.inode.Size), nil
}

func (s *Storage) GetTotalSize() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	for _, inodeData := range s.inodeData {
		if !inodeData.inode.IsDir() {
			total += int64(inodeData.inode.Size)
		}
	}
	return total
}

func (s *Storage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for ino := range s.inodeData {
		s.syncInode(ino)
	}

	s.sb.State = domain.StateClean
	s.writeSuperblock()

	return s.file.Close()
}

func (s *Storage) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for ino, inodeData := range s.inodeData {
		if inodeData.dirty {
			s.syncInode(ino)
		}
	}
	return s.file.Sync()
}

func (s *Storage) Truncate(ino uint64, size int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	inodeData, ok := s.inodeData[ino]
	if !ok {
		return ErrNotFound
	}

	if inodeData.inode.IsDir() {
		return ErrIsDir
	}

	data := inodeData.data
	if data == nil {
		data = []byte{}
	}

	if int64(len(data)) > size {
		data = data[:size]
	} else if int64(len(data)) < size {
		newData := make([]byte, size)
		copy(newData, data)
		data = newData
	}

	inodeData.data = data
	inodeData.inode.Size = uint64(size)
	now := time.Now()
	inodeData.inode.Mtime = now
	inodeData.inode.Ctime = now
	inodeData.dirty = true

	s.syncInode(ino)
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

	oldParentData, ok := s.inodeData[oldParentIno]
	if !ok {
		return 0, ErrNotFound
	}
	if !oldParentData.inode.IsDir() {
		return 0, ErrNotDir
	}

	newParentData, ok := s.inodeData[newParentIno]
	if !ok {
		return 0, ErrNotFound
	}
	if !newParentData.inode.IsDir() {
		return 0, ErrNotDir
	}

	srcIdx := -1
	var srcIno uint64
	var srcMode uint32
	for i, e := range oldParentData.dirEntries {
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

	srcData, ok := s.inodeData[srcIno]
	if !ok {
		return 0, ErrNotFound
	}

	if oldParentIno == newParentIno && oldName == newName {
		return srcIno, nil
	}

	dstIdx := -1
	var dstIno uint64
	for i, e := range newParentData.dirEntries {
		if e.Name == newName {
			dstIdx = i
			dstIno = e.Ino
			break
		}
	}

	if dstIdx != -1 {
		dstData, ok := s.inodeData[dstIno]
		if !ok {
			return 0, ErrNotFound
		}

		if srcData.inode.IsDir() && !dstData.inode.IsDir() {
			return 0, ErrNotDir
		}
		if !srcData.inode.IsDir() && dstData.inode.IsDir() {
			return 0, ErrIsDir
		}

		if dstData.inode.IsDir() {
			if len(dstData.dirEntries) > 0 {
				return 0, ErrNotEmpty
			}
			delete(s.inodeData, dstIno)
			newParentData.dirEntries = append(newParentData.dirEntries[:dstIdx], newParentData.dirEntries[dstIdx+1:]...)
			if newParentData.inode.Nlink > 0 {
				newParentData.inode.Nlink--
			}
		} else {
			dstData.inode.Nlink--
			if dstData.inode.Nlink == 0 {
				delete(s.inodeData, dstIno)
			}
			newParentData.dirEntries = append(newParentData.dirEntries[:dstIdx], newParentData.dirEntries[dstIdx+1:]...)
		}
	}

	oldParentData.dirEntries = append(oldParentData.dirEntries[:srcIdx], oldParentData.dirEntries[srcIdx+1:]...)

	entry := domain.DirEntry{
		Ino:  srcIno,
		Mode: srcMode,
		Name: newName,
	}
	newParentData.dirEntries = append(newParentData.dirEntries, entry)

	now := time.Now()

	if srcData.inode.IsDir() && oldParentIno != newParentIno {
		if oldParentData.inode.Nlink > 0 {
			oldParentData.inode.Nlink--
		}
		newParentData.inode.Nlink++
	}

	oldParentData.inode.Mtime, oldParentData.inode.Ctime = now, now
	newParentData.inode.Mtime, newParentData.inode.Ctime = now, now
	srcData.inode.Ctime = now
	oldParentData.dirty = true
	newParentData.dirty = true
	srcData.dirty = true

	s.syncInode(oldParentIno)
	if oldParentIno != newParentIno {
		s.syncInode(newParentIno)
	}
	s.syncInode(srcIno)

	return srcIno, nil
}

func (s *Storage) GetFileData(ino uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	inodeData, ok := s.inodeData[ino]
	if !ok {
		return nil, ErrNotFound
	}

	if inodeData.inode.IsDir() {
		return nil, ErrIsDir
	}

	result := make([]byte, len(inodeData.data))
	copy(result, inodeData.data)
	return result, nil
}

func (s *Storage) WalkPath(path string) (*domain.Inode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if path == "" || path == "/" {
		return s.inodeData[RootIno].inode, nil
	}

	parts := splitPath(path)
	currentIno := uint64(RootIno)

	for _, part := range parts {
		if part == "" {
			continue
		}

		currentData, ok := s.inodeData[currentIno]
		if !ok {
			return nil, ErrNotFound
		}

		if !currentData.inode.IsDir() {
			return nil, ErrNotDir
		}

		found := false
		for _, entry := range currentData.dirEntries {
			if entry.Name == part {
				currentIno = entry.Ino
				found = true
				break
			}
		}

		if !found {
			return nil, ErrNotFound
		}
	}

	inodeData, ok := s.inodeData[currentIno]
	if !ok {
		return nil, ErrNotFound
	}

	return inodeData.inode, nil
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, c := range path {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

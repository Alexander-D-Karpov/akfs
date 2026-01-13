package storage

import (
	"encoding/binary"
	"hash/crc32"
	"os"
	"sync"
)

const (
	WALMagic      = 0x574C4F47
	WALFrameSize  = 24 + PageSize
	WALHeaderSize = 24
)

type WALFrame struct {
	PageNum  uint32
	Checksum uint32
	Salt1    uint32
	Salt2    uint32
	DBSize   uint32
	Reserved uint32
	Data     []byte
}

type WAL struct {
	mu     sync.Mutex
	file   *os.File
	path   string
	salt1  uint32
	salt2  uint32
	frames int
}

func NewWAL(path string) (*WAL, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	w := &WAL{
		file:  f,
		path:  path,
		salt1: 0x12345678,
		salt2: 0x87654321,
	}

	return w, nil
}

func (w *WAL) WriteFrame(pageNum uint32, data []byte, commit bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	frame := make([]byte, WALFrameSize)
	binary.LittleEndian.PutUint32(frame[0:4], pageNum)
	binary.LittleEndian.PutUint32(frame[8:12], w.salt1)
	binary.LittleEndian.PutUint32(frame[12:16], w.salt2)

	if commit {
		binary.LittleEndian.PutUint32(frame[16:20], 1)
	}

	copy(frame[WALHeaderSize:], data)

	checksum := crc32.ChecksumIEEE(frame[WALHeaderSize:])
	binary.LittleEndian.PutUint32(frame[4:8], checksum)

	offset := int64(w.frames * WALFrameSize)
	if _, err := w.file.WriteAt(frame, offset); err != nil {
		return err
	}

	w.frames++

	if commit {
		return w.file.Sync()
	}

	return nil
}

func (w *WAL) Checkpoint(storage *Storage) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.frames = 0
	w.salt1++

	return w.file.Truncate(0)
}

func (w *WAL) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.file.Close()
}

func (w *WAL) Recover() ([]WALFrame, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	info, err := w.file.Stat()
	if err != nil {
		return nil, err
	}

	numFrames := int(info.Size() / WALFrameSize)
	frames := make([]WALFrame, 0, numFrames)

	for i := 0; i < numFrames; i++ {
		buf := make([]byte, WALFrameSize)
		offset := int64(i * WALFrameSize)
		if _, err := w.file.ReadAt(buf, offset); err != nil {
			break
		}

		frame := WALFrame{
			PageNum:  binary.LittleEndian.Uint32(buf[0:4]),
			Checksum: binary.LittleEndian.Uint32(buf[4:8]),
			Salt1:    binary.LittleEndian.Uint32(buf[8:12]),
			Salt2:    binary.LittleEndian.Uint32(buf[12:16]),
			DBSize:   binary.LittleEndian.Uint32(buf[16:20]),
			Data:     make([]byte, PageSize),
		}
		copy(frame.Data, buf[WALHeaderSize:])

		expectedChecksum := crc32.ChecksumIEEE(buf[WALHeaderSize:])
		if frame.Checksum != expectedChecksum {
			break
		}

		frames = append(frames, frame)

		if frame.DBSize > 0 {
			break
		}
	}

	return frames, nil
}

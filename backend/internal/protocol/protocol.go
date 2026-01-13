package protocol

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderSize   = 24
	MaxMsgSize   = 16 * 1024 * 1024
	MaxNameLen   = 255
	ProtoVersion = 1
	PageSize     = 4096
	RootIno      = 1
)

const (
	OpInit     uint16 = 0x01
	OpDestroy  uint16 = 0x02
	OpLookup   uint16 = 0x10
	OpGetattr  uint16 = 0x11
	OpSetattr  uint16 = 0x12
	OpReaddir  uint16 = 0x20
	OpCreate   uint16 = 0x30
	OpMkdir    uint16 = 0x31
	OpUnlink   uint16 = 0x32
	OpRmdir    uint16 = 0x33
	OpLink     uint16 = 0x34
	OpRename   uint16 = 0x35
	OpRead     uint16 = 0x40
	OpWrite    uint16 = 0x41
	OpTruncate        = 0x42
	OpWatch    uint16 = 0x50
	OpUnwatch  uint16 = 0x51
	OpNotify   uint16 = 0x52
)

const (
	FlagEncrypted uint16 = 0x0001
	FlagResponse  uint16 = 0x8000
)

const (
	ErrNone      int32 = 0
	ErrNoent     int32 = -2
	ErrIO        int32 = -5
	ErrNomem     int32 = -12
	ErrExist     int32 = -17
	ErrNotdir    int32 = -20
	ErrIsdir     int32 = -21
	ErrInval     int32 = -22
	ErrNospc     int32 = -28
	ErrNotempty  int32 = -39
	ErrProto     int32 = -71
	ErrConnreset int32 = -104
	ErrTimedout  int32 = -110
	ErrRofs      int32 = -30
	ErrPerm      int32 = -1
)

const (
	S_IFMT  uint32 = 0170000
	S_IFDIR uint32 = 0040000
	S_IFREG uint32 = 0100000
	S_IRWXU uint32 = 00700
	S_IRWXG uint32 = 00070
	S_IRWXO uint32 = 00007
)

const (
	NotifyCreate uint32 = 1 << iota
	NotifyDelete
	NotifyModify
	NotifyAttrib
)

var (
	ErrMsgTooShort = errors.New("message too short")
	ErrMsgTooLarge = errors.New("message too large")
	ErrBadMagic    = errors.New("bad magic")
	ErrBadVersion  = errors.New("bad version")
	ErrInvalidOp   = errors.New("invalid operation")
)

type Header struct {
	Length uint32
	Opcode uint16
	Flags  uint16
	TxnID  uint64
	NodeID uint64
}

func (h *Header) Encode(buf []byte) {
	binary.LittleEndian.PutUint32(buf[0:4], h.Length)
	binary.LittleEndian.PutUint16(buf[4:6], h.Opcode)
	binary.LittleEndian.PutUint16(buf[6:8], h.Flags)
	binary.LittleEndian.PutUint64(buf[8:16], h.TxnID)
	binary.LittleEndian.PutUint64(buf[16:24], h.NodeID)
}

func (h *Header) Decode(buf []byte) error {
	if len(buf) < HeaderSize {
		return ErrMsgTooShort
	}
	h.Length = binary.LittleEndian.Uint32(buf[0:4])
	h.Opcode = binary.LittleEndian.Uint16(buf[4:6])
	h.Flags = binary.LittleEndian.Uint16(buf[6:8])
	h.TxnID = binary.LittleEndian.Uint64(buf[8:16])
	h.NodeID = binary.LittleEndian.Uint64(buf[16:24])
	return nil
}

type InitRequest struct {
	Version uint32
	MaxSize uint32
	Token   string
}

func (r *InitRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], r.Version)
	binary.LittleEndian.PutUint32(buf[4:8], r.MaxSize)

	tok := []byte(r.Token)
	if len(tok) > MaxNameLen {
		tok = tok[:MaxNameLen]
	}

	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(tok)))
	copy(buf[10:], tok)
	return 10 + len(tok)
}

func (r *InitRequest) Decode(buf []byte) error {
	if len(buf) < 8 {
		return ErrMsgTooShort
	}
	r.Version = binary.LittleEndian.Uint32(buf[0:4])
	r.MaxSize = binary.LittleEndian.Uint32(buf[4:8])

	if len(buf) == 8 {
		r.Token = ""
		return nil
	}

	if len(buf) < 10 {
		return ErrMsgTooShort
	}
	n := int(binary.LittleEndian.Uint16(buf[8:10]))
	if n < 0 || len(buf) < 10+n {
		return ErrMsgTooShort
	}
	r.Token = string(buf[10 : 10+n])
	return nil
}

type InitResponse struct {
	Error   int32
	Version uint32
	MaxSize uint32
}

func (r *InitResponse) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], uint32(r.Error))
	binary.LittleEndian.PutUint32(buf[4:8], r.Version)
	binary.LittleEndian.PutUint32(buf[8:12], r.MaxSize)
	return 12
}

func (r *InitResponse) Decode(buf []byte) error {
	if len(buf) < 12 {
		return ErrMsgTooShort
	}
	r.Error = int32(binary.LittleEndian.Uint32(buf[0:4]))
	r.Version = binary.LittleEndian.Uint32(buf[4:8])
	r.MaxSize = binary.LittleEndian.Uint32(buf[8:12])
	return nil
}

type LookupRequest struct {
	Name string
}

func (r *LookupRequest) Encode(buf []byte) int {
	n := len(r.Name)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(n))
	copy(buf[2:], r.Name)
	return 2 + n
}

func (r *LookupRequest) Decode(buf []byte) error {
	if len(buf) < 2 {
		return ErrMsgTooShort
	}
	n := int(binary.LittleEndian.Uint16(buf[0:2]))
	if len(buf) < 2+n {
		return ErrMsgTooShort
	}
	r.Name = string(buf[2 : 2+n])
	return nil
}

type AttrResponse struct {
	Error int32
	Ino   uint64
	Mode  uint32
	Nlink uint32
	Size  uint64
	Atime uint64
	Mtime uint64
	Ctime uint64
}

func (r *AttrResponse) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], uint32(r.Error))
	binary.LittleEndian.PutUint64(buf[4:12], r.Ino)
	binary.LittleEndian.PutUint32(buf[12:16], r.Mode)
	binary.LittleEndian.PutUint32(buf[16:20], r.Nlink)
	binary.LittleEndian.PutUint64(buf[20:28], r.Size)
	binary.LittleEndian.PutUint64(buf[28:36], r.Atime)
	binary.LittleEndian.PutUint64(buf[36:44], r.Mtime)
	binary.LittleEndian.PutUint64(buf[44:52], r.Ctime)
	return 52
}

func (r *AttrResponse) Decode(buf []byte) error {
	if len(buf) < 52 {
		return ErrMsgTooShort
	}
	r.Error = int32(binary.LittleEndian.Uint32(buf[0:4]))
	r.Ino = binary.LittleEndian.Uint64(buf[4:12])
	r.Mode = binary.LittleEndian.Uint32(buf[12:16])
	r.Nlink = binary.LittleEndian.Uint32(buf[16:20])
	r.Size = binary.LittleEndian.Uint64(buf[20:28])
	r.Atime = binary.LittleEndian.Uint64(buf[28:36])
	r.Mtime = binary.LittleEndian.Uint64(buf[36:44])
	r.Ctime = binary.LittleEndian.Uint64(buf[44:52])
	return nil
}

type ReaddirRequest struct {
	Offset uint64
	Count  uint32
}

func (r *ReaddirRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.Offset)
	binary.LittleEndian.PutUint32(buf[8:12], r.Count)
	return 12
}

func (r *ReaddirRequest) Decode(buf []byte) error {
	if len(buf) < 12 {
		return ErrMsgTooShort
	}
	r.Offset = binary.LittleEndian.Uint64(buf[0:8])
	r.Count = binary.LittleEndian.Uint32(buf[8:12])
	return nil
}

type DirEntry struct {
	Ino  uint64
	Mode uint32
	Name string
}

type ReaddirResponse struct {
	Error   int32
	Entries []DirEntry
}

func (r *ReaddirResponse) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], uint32(r.Error))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(r.Entries)))
	off := 8
	for _, e := range r.Entries {
		binary.LittleEndian.PutUint64(buf[off:off+8], e.Ino)
		binary.LittleEndian.PutUint32(buf[off+8:off+12], e.Mode)
		n := len(e.Name)
		binary.LittleEndian.PutUint16(buf[off+12:off+14], uint16(n))
		copy(buf[off+14:], e.Name)
		off += 14 + n
	}
	return off
}

func (r *ReaddirResponse) Decode(buf []byte) error {
	if len(buf) < 8 {
		return ErrMsgTooShort
	}
	r.Error = int32(binary.LittleEndian.Uint32(buf[0:4]))
	count := int(binary.LittleEndian.Uint32(buf[4:8]))
	r.Entries = make([]DirEntry, 0, count)
	off := 8
	for i := 0; i < count; i++ {
		if len(buf) < off+14 {
			return ErrMsgTooShort
		}
		ino := binary.LittleEndian.Uint64(buf[off : off+8])
		mode := binary.LittleEndian.Uint32(buf[off+8 : off+12])
		n := int(binary.LittleEndian.Uint16(buf[off+12 : off+14]))
		if len(buf) < off+14+n {
			return ErrMsgTooShort
		}
		name := string(buf[off+14 : off+14+n])
		r.Entries = append(r.Entries, DirEntry{Ino: ino, Mode: mode, Name: name})
		off += 14 + n
	}
	return nil
}

type CreateRequest struct {
	Mode uint32
	Name string
}

func (r *CreateRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], r.Mode)
	n := len(r.Name)
	binary.LittleEndian.PutUint16(buf[4:6], uint16(n))
	copy(buf[6:], r.Name)
	return 6 + n
}

func (r *CreateRequest) Decode(buf []byte) error {
	if len(buf) < 6 {
		return ErrMsgTooShort
	}
	r.Mode = binary.LittleEndian.Uint32(buf[0:4])
	n := int(binary.LittleEndian.Uint16(buf[4:6]))
	if len(buf) < 6+n {
		return ErrMsgTooShort
	}
	r.Name = string(buf[6 : 6+n])
	return nil
}

type UnlinkRequest struct {
	Name string
}

func (r *UnlinkRequest) Encode(buf []byte) int {
	n := len(r.Name)
	binary.LittleEndian.PutUint16(buf[0:2], uint16(n))
	copy(buf[2:], r.Name)
	return 2 + n
}

func (r *UnlinkRequest) Decode(buf []byte) error {
	if len(buf) < 2 {
		return ErrMsgTooShort
	}
	n := int(binary.LittleEndian.Uint16(buf[0:2]))
	if len(buf) < 2+n {
		return ErrMsgTooShort
	}
	r.Name = string(buf[2 : 2+n])
	return nil
}

type LinkRequest struct {
	NewParentIno uint64
	NewName      string
}

func (r *LinkRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.NewParentIno)
	n := len(r.NewName)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(n))
	copy(buf[10:], r.NewName)
	return 10 + n
}

func (r *LinkRequest) Decode(buf []byte) error {
	if len(buf) < 10 {
		return ErrMsgTooShort
	}
	r.NewParentIno = binary.LittleEndian.Uint64(buf[0:8])
	n := int(binary.LittleEndian.Uint16(buf[8:10]))
	if len(buf) < 10+n {
		return ErrMsgTooShort
	}
	r.NewName = string(buf[10 : 10+n])
	return nil
}

type ReadRequest struct {
	Offset uint64
	Size   uint32
}

func (r *ReadRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.Offset)
	binary.LittleEndian.PutUint32(buf[8:12], r.Size)
	return 12
}

func (r *ReadRequest) Decode(buf []byte) error {
	if len(buf) < 12 {
		return ErrMsgTooShort
	}
	r.Offset = binary.LittleEndian.Uint64(buf[0:8])
	r.Size = binary.LittleEndian.Uint32(buf[8:12])
	return nil
}

type ReadResponse struct {
	Error int32
	Data  []byte
}

func (r *ReadResponse) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], uint32(r.Error))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(len(r.Data)))
	copy(buf[8:], r.Data)
	return 8 + len(r.Data)
}

func (r *ReadResponse) Decode(buf []byte) error {
	if len(buf) < 8 {
		return ErrMsgTooShort
	}
	r.Error = int32(binary.LittleEndian.Uint32(buf[0:4]))
	n := int(binary.LittleEndian.Uint32(buf[4:8]))
	if len(buf) < 8+n {
		return ErrMsgTooShort
	}
	r.Data = make([]byte, n)
	copy(r.Data, buf[8:8+n])
	return nil
}

type WriteRequest struct {
	Offset uint64
	Data   []byte
}

func (r *WriteRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.Offset)
	binary.LittleEndian.PutUint32(buf[8:12], uint32(len(r.Data)))
	copy(buf[12:], r.Data)
	return 12 + len(r.Data)
}

func (r *WriteRequest) Decode(buf []byte) error {
	if len(buf) < 12 {
		return ErrMsgTooShort
	}
	r.Offset = binary.LittleEndian.Uint64(buf[0:8])
	n := int(binary.LittleEndian.Uint32(buf[8:12]))
	if len(buf) < 12+n {
		return ErrMsgTooShort
	}
	r.Data = make([]byte, n)
	copy(r.Data, buf[12:12+n])
	return nil
}

type WriteResponse struct {
	Error   int32
	Written uint32
	NewSize uint64
}

func (r *WriteResponse) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], uint32(r.Error))
	binary.LittleEndian.PutUint32(buf[4:8], r.Written)
	binary.LittleEndian.PutUint64(buf[8:16], r.NewSize)
	return 16
}

func (r *WriteResponse) Decode(buf []byte) error {
	if len(buf) < 16 {
		return ErrMsgTooShort
	}
	r.Error = int32(binary.LittleEndian.Uint32(buf[0:4]))
	r.Written = binary.LittleEndian.Uint32(buf[4:8])
	r.NewSize = binary.LittleEndian.Uint64(buf[8:16])
	return nil
}

type ErrorResponse struct {
	Error int32
}

func (r *ErrorResponse) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], uint32(r.Error))
	return 4
}

func (r *ErrorResponse) Decode(buf []byte) error {
	if len(buf) < 4 {
		return ErrMsgTooShort
	}
	r.Error = int32(binary.LittleEndian.Uint32(buf[0:4]))
	return nil
}

type WatchRequest struct {
	Events uint32
}

func (r *WatchRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint32(buf[0:4], r.Events)
	return 4
}

func (r *WatchRequest) Decode(buf []byte) error {
	if len(buf) < 4 {
		return ErrMsgTooShort
	}
	r.Events = binary.LittleEndian.Uint32(buf[0:4])
	return nil
}

type NotifyEvent struct {
	ParentIno uint64
	Ino       uint64
	Event     uint32
	Name      string
}

func (r *NotifyEvent) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.ParentIno)
	binary.LittleEndian.PutUint64(buf[8:16], r.Ino)
	binary.LittleEndian.PutUint32(buf[16:20], r.Event)
	n := len(r.Name)
	binary.LittleEndian.PutUint16(buf[20:22], uint16(n))
	copy(buf[22:], r.Name)
	return 22 + n
}

func (r *NotifyEvent) Decode(buf []byte) error {
	if len(buf) < 22 {
		return ErrMsgTooShort
	}
	r.ParentIno = binary.LittleEndian.Uint64(buf[0:8])
	r.Ino = binary.LittleEndian.Uint64(buf[8:16])
	r.Event = binary.LittleEndian.Uint32(buf[16:20])
	n := int(binary.LittleEndian.Uint16(buf[20:22]))
	if len(buf) < 22+n {
		return ErrMsgTooShort
	}
	r.Name = string(buf[22 : 22+n])
	return nil
}

type TruncateRequest struct {
	Size uint64
}

func (r *TruncateRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.Size)
	return 8
}

func (r *TruncateRequest) Decode(buf []byte) error {
	if len(buf) < 8 {
		return ErrMsgTooShort
	}
	r.Size = binary.LittleEndian.Uint64(buf[0:8])
	return nil
}

type RenameRequest struct {
	NewParentIno uint64
	OldName      string
	NewName      string
}

func (r *RenameRequest) Encode(buf []byte) int {
	binary.LittleEndian.PutUint64(buf[0:8], r.NewParentIno)

	oldb := []byte(r.OldName)
	if len(oldb) > MaxNameLen {
		oldb = oldb[:MaxNameLen]
	}
	newb := []byte(r.NewName)
	if len(newb) > MaxNameLen {
		newb = newb[:MaxNameLen]
	}

	off := 8
	binary.LittleEndian.PutUint16(buf[off:off+2], uint16(len(oldb)))
	off += 2
	copy(buf[off:], oldb)
	off += len(oldb)

	binary.LittleEndian.PutUint16(buf[off:off+2], uint16(len(newb)))
	off += 2
	copy(buf[off:], newb)
	off += len(newb)

	return off
}

func (r *RenameRequest) Decode(buf []byte) error {
	if len(buf) < 8+2 {
		return ErrMsgTooShort
	}

	r.NewParentIno = binary.LittleEndian.Uint64(buf[0:8])
	off := 8

	if len(buf) < off+2 {
		return ErrMsgTooShort
	}
	oldN := int(binary.LittleEndian.Uint16(buf[off : off+2]))
	off += 2
	if oldN < 0 || oldN > MaxNameLen || len(buf) < off+oldN {
		return ErrMsgTooShort
	}
	r.OldName = string(buf[off : off+oldN])
	off += oldN

	if len(buf) < off+2 {
		return ErrMsgTooShort
	}
	newN := int(binary.LittleEndian.Uint16(buf[off : off+2]))
	off += 2
	if newN < 0 || newN > MaxNameLen || len(buf) < off+newN {
		return ErrMsgTooShort
	}
	r.NewName = string(buf[off : off+newN])

	return nil
}

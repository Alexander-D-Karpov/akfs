package server

import (
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/crypto"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/protocol"
	"github.com/Alexander-D-Karpov/akfs/backend/internal/storage"
)

type Server struct {
	listener     net.Listener
	storage      *storage.Storage
	crypto       *crypto.AESCrypto
	notify       *NotifyManager
	authToken    string
	maxSize      int64
	clients      map[uint64]*Client
	clientsMu    sync.RWMutex
	nextClientID uint64
	quit         chan struct{}
	wg           sync.WaitGroup
}

type Client struct {
	id            uint64
	conn          net.Conn
	server        *Server
	crypto        *crypto.AESCrypto
	authenticated bool
	readOnly      bool
	mu            sync.Mutex
	notifyChan    chan *protocol.NotifyEvent
	quit          chan struct{}
}

func NewServer(storage *storage.Storage, cryptoKey []byte, authToken string, maxSize int64) (*Server, error) {
	c, err := crypto.NewAESCrypto(cryptoKey)
	if err != nil {
		return nil, err
	}

	return &Server{
		storage:   storage,
		crypto:    c,
		notify:    NewNotifyManager(),
		authToken: authToken,
		maxSize:   maxSize,
		clients:   make(map[uint64]*Client),
		quit:      make(chan struct{}),
	}, nil
}

func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.listener = ln
	log.Printf("Server listening on %s", addr)

	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		clientID := atomic.AddUint64(&s.nextClientID, 1)
		log.Printf("Client %d connected from %s", clientID, conn.RemoteAddr())

		client := &Client{
			id:         clientID,
			conn:       conn,
			server:     s,
			crypto:     s.crypto,
			notifyChan: make(chan *protocol.NotifyEvent, 100),
			quit:       make(chan struct{}),
		}

		s.clientsMu.Lock()
		s.clients[clientID] = client
		s.clientsMu.Unlock()

		s.notify.RegisterClient(client)

		s.wg.Add(2)
		go client.readLoop()
		go client.notifyLoop()
	}
}

func (s *Server) Stop() {
	close(s.quit)
	s.listener.Close()

	s.clientsMu.Lock()
	for _, client := range s.clients {
		client.Close()
	}
	s.clientsMu.Unlock()

	s.wg.Wait()
	s.storage.Close()
}

func (c *Client) readLoop() {
	defer func() {
		c.server.wg.Done()
		c.cleanup()
	}()

	headerBuf := make([]byte, protocol.HeaderSize)

	for {
		select {
		case <-c.quit:
			return
		default:
		}

		c.conn.SetReadDeadline(time.Now().Add(300 * time.Second))

		n, err := io.ReadFull(c.conn, headerBuf)
		if err != nil {
			if err != io.EOF {
				log.Printf("Client %d read header error (read %d bytes): %v", c.id, n, err)
			} else {
				log.Printf("Client %d disconnected", c.id)
			}
			return
		}

		var hdr protocol.Header
		if err := hdr.Decode(headerBuf); err != nil {
			log.Printf("Client %d decode header error: %v", c.id, err)
			return
		}

		log.Printf("Client %d received: op=0x%02x len=%d txn=%d node=%d",
			c.id, hdr.Opcode, hdr.Length, hdr.TxnID, hdr.NodeID)

		if hdr.Length > protocol.MaxMsgSize {
			log.Printf("Client %d message too large: %d", c.id, hdr.Length)
			return
		}

		payloadLen := int(hdr.Length) - protocol.HeaderSize
		var payload []byte
		if payloadLen > 0 {
			payload = make([]byte, payloadLen)
			n, err = io.ReadFull(c.conn, payload)
			if err != nil {
				log.Printf("Client %d read payload error (read %d/%d bytes): %v", c.id, n, payloadLen, err)
				return
			}
		}

		if (hdr.Flags & protocol.FlagEncrypted) != 0 {
			decrypted, err := c.crypto.Decrypt(payload)
			if err != nil {
				log.Printf("Client %d decrypt error: %v", c.id, err)
				c.sendError(&hdr, protocol.ErrProto)
				continue
			}
			payload = decrypted
		}

		c.handleMessage(&hdr, payload)
	}
}

func (c *Client) notifyLoop() {
	defer c.server.wg.Done()

	for {
		select {
		case <-c.quit:
			return
		case ev := <-c.notifyChan:
			c.sendNotifyEvent(ev)
		}
	}
}

func (c *Client) SendNotification(ev *protocol.NotifyEvent) {
	select {
	case c.notifyChan <- ev:
	default:
	}
}

func (c *Client) sendNotifyEvent(ev *protocol.NotifyEvent) {
	buf := make([]byte, protocol.HeaderSize+256)

	hdr := protocol.Header{
		Opcode: protocol.OpNotify,
		Flags:  protocol.FlagResponse,
		TxnID:  0,
		NodeID: ev.ParentIno,
	}

	payloadLen := ev.Encode(buf[protocol.HeaderSize:])
	hdr.Length = uint32(protocol.HeaderSize + payloadLen)
	hdr.Encode(buf)

	c.mu.Lock()
	c.conn.Write(buf[:hdr.Length])
	c.mu.Unlock()
}

func (c *Client) handleMessage(hdr *protocol.Header, payload []byte) {
	// Must INIT first (except DESTROY)
	if !c.authenticated && hdr.Opcode != protocol.OpInit && hdr.Opcode != protocol.OpDestroy {
		c.sendError(hdr, protocol.ErrPerm)
		return
	}

	switch hdr.Opcode {
	case protocol.OpInit:
		c.handleInit(hdr, payload)
	case protocol.OpDestroy:
		c.Close()
	case protocol.OpLookup:
		c.handleLookup(hdr, payload)
	case protocol.OpGetattr:
		c.handleGetattr(hdr, payload)
	case protocol.OpReaddir:
		c.handleReaddir(hdr, payload)
	case protocol.OpCreate:
		c.handleCreate(hdr, payload)
	case protocol.OpMkdir:
		c.handleMkdir(hdr, payload)
	case protocol.OpUnlink:
		c.handleUnlink(hdr, payload)
	case protocol.OpRmdir:
		c.handleRmdir(hdr, payload)
	case protocol.OpLink:
		c.handleLink(hdr, payload)
	case protocol.OpRename:
		c.handleRename(hdr, payload)
	case protocol.OpRead:
		c.handleRead(hdr, payload)
	case protocol.OpWrite:
		c.handleWrite(hdr, payload)
	case protocol.OpWatch:
		c.handleWatch(hdr, payload)
	case protocol.OpUnwatch:
		c.handleUnwatch(hdr, payload)
	case protocol.OpTruncate:
		c.handleTruncate(hdr, payload)
	default:
		log.Printf("Client %d unknown opcode: 0x%02x", c.id, hdr.Opcode)
		c.sendError(hdr, protocol.ErrInval)
	}
}

func (c *Client) handleInit(hdr *protocol.Header, payload []byte) {
	var req protocol.InitRequest
	if err := req.Decode(payload); err != nil {
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	// default: allow read-only without token
	if req.Token == "" {
		c.authenticated = true
		c.readOnly = true
	} else if req.Token != c.server.authToken {
		// token provided but wrong -> fail mount
		resp := protocol.InitResponse{
			Error:   protocol.ErrPerm,
			Version: protocol.ProtoVersion,
			MaxSize: protocol.MaxMsgSize,
		}
		c.sendResponse(hdr, &resp)
		c.Close()
		return
	} else {
		// valid token -> RW
		c.authenticated = true
		c.readOnly = false
	}

	resp := protocol.InitResponse{
		Error:   protocol.ErrNone,
		Version: protocol.ProtoVersion,
		MaxSize: protocol.MaxMsgSize,
	}
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleLookup(hdr *protocol.Header, payload []byte) {
	var req protocol.LookupRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d LOOKUP decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d LOOKUP: parent=%d name=%q", c.id, hdr.NodeID, req.Name)

	inode, err := c.server.storage.Lookup(hdr.NodeID, req.Name)
	if err != nil {
		log.Printf("Client %d LOOKUP error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	resp := protocol.AttrResponse{
		Error: protocol.ErrNone,
		Ino:   inode.Ino,
		Mode:  inode.Mode,
		Nlink: inode.Nlink,
		Size:  inode.Size,
		Atime: uint64(inode.Atime.Unix()),
		Mtime: uint64(inode.Mtime.Unix()),
		Ctime: uint64(inode.Ctime.Unix()),
	}

	log.Printf("Client %d LOOKUP result: ino=%d mode=0%o size=%d", c.id, inode.Ino, inode.Mode, inode.Size)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleGetattr(hdr *protocol.Header, payload []byte) {
	log.Printf("Client %d GETATTR: ino=%d", c.id, hdr.NodeID)

	inode, err := c.server.storage.GetInode(hdr.NodeID)
	if err != nil {
		log.Printf("Client %d GETATTR error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	resp := protocol.AttrResponse{
		Error: protocol.ErrNone,
		Ino:   inode.Ino,
		Mode:  inode.Mode,
		Nlink: inode.Nlink,
		Size:  inode.Size,
		Atime: uint64(inode.Atime.Unix()),
		Mtime: uint64(inode.Mtime.Unix()),
		Ctime: uint64(inode.Ctime.Unix()),
	}

	log.Printf("Client %d GETATTR result: mode=0%o size=%d nlink=%d", c.id, inode.Mode, inode.Size, inode.Nlink)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleReaddir(hdr *protocol.Header, payload []byte) {
	var req protocol.ReaddirRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d READDIR decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d READDIR: ino=%d offset=%d count=%d", c.id, hdr.NodeID, req.Offset, req.Count)

	entries, err := c.server.storage.List(hdr.NodeID)
	if err != nil {
		log.Printf("Client %d READDIR error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	protoEntries := make([]protocol.DirEntry, len(entries))
	for i, e := range entries {
		protoEntries[i] = protocol.DirEntry{
			Ino:  e.Ino,
			Mode: e.Mode,
			Name: e.Name,
		}
	}

	resp := protocol.ReaddirResponse{
		Error:   protocol.ErrNone,
		Entries: protoEntries,
	}

	log.Printf("Client %d READDIR result: %d entries", c.id, len(entries))
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleCreate(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d CREATE denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.CreateRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d CREATE decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d CREATE: parent=%d name=%q mode=0%o", c.id, hdr.NodeID, req.Name, req.Mode)

	inode, err := c.server.storage.Create(hdr.NodeID, req.Name, req.Mode)
	if err != nil {
		log.Printf("Client %d CREATE error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	c.server.notify.NotifyCreate(hdr.NodeID, inode.Ino, req.Name)

	resp := protocol.AttrResponse{
		Error: protocol.ErrNone,
		Ino:   inode.Ino,
		Mode:  inode.Mode,
		Nlink: inode.Nlink,
		Size:  inode.Size,
		Atime: uint64(inode.Atime.Unix()),
		Mtime: uint64(inode.Mtime.Unix()),
		Ctime: uint64(inode.Ctime.Unix()),
	}

	log.Printf("Client %d CREATE result: ino=%d", c.id, inode.Ino)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleMkdir(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d MKDIR denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.CreateRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d MKDIR decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d MKDIR: parent=%d name=%q mode=0%o", c.id, hdr.NodeID, req.Name, req.Mode)

	inode, err := c.server.storage.Mkdir(hdr.NodeID, req.Name, req.Mode)
	if err != nil {
		log.Printf("Client %d MKDIR error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	c.server.notify.NotifyCreate(hdr.NodeID, inode.Ino, req.Name)

	resp := protocol.AttrResponse{
		Error: protocol.ErrNone,
		Ino:   inode.Ino,
		Mode:  inode.Mode,
		Nlink: inode.Nlink,
		Size:  inode.Size,
		Atime: uint64(inode.Atime.Unix()),
		Mtime: uint64(inode.Mtime.Unix()),
		Ctime: uint64(inode.Ctime.Unix()),
	}

	log.Printf("Client %d MKDIR result: ino=%d", c.id, inode.Ino)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleUnlink(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d UNLINK denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.UnlinkRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d UNLINK decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d UNLINK: parent=%d name=%q", c.id, hdr.NodeID, req.Name)

	inode, _ := c.server.storage.Lookup(hdr.NodeID, req.Name)
	var deletedIno uint64
	if inode != nil {
		deletedIno = inode.Ino
	}

	if err := c.server.storage.Unlink(hdr.NodeID, req.Name); err != nil {
		log.Printf("Client %d UNLINK error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	c.server.notify.NotifyDelete(hdr.NodeID, deletedIno, req.Name)

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	log.Printf("Client %d UNLINK complete", c.id)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleRmdir(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d RMDIR denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.UnlinkRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d RMDIR decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d RMDIR: parent=%d name=%q", c.id, hdr.NodeID, req.Name)

	inode, _ := c.server.storage.Lookup(hdr.NodeID, req.Name)
	var deletedIno uint64
	if inode != nil {
		deletedIno = inode.Ino
	}

	if err := c.server.storage.Rmdir(hdr.NodeID, req.Name); err != nil {
		log.Printf("Client %d RMDIR error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	c.server.notify.NotifyDelete(hdr.NodeID, deletedIno, req.Name)

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	log.Printf("Client %d RMDIR complete", c.id)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleLink(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d LINK denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.LinkRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d LINK decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d LINK: ino=%d newparent=%d newname=%q", c.id, hdr.NodeID, req.NewParentIno, req.NewName)

	if err := c.server.storage.Link(hdr.NodeID, req.NewParentIno, req.NewName); err != nil {
		log.Printf("Client %d LINK error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	c.server.notify.NotifyCreate(req.NewParentIno, hdr.NodeID, req.NewName)

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	log.Printf("Client %d LINK complete", c.id)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleRead(hdr *protocol.Header, payload []byte) {
	var req protocol.ReadRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d READ decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d READ: ino=%d offset=%d size=%d", c.id, hdr.NodeID, req.Offset, req.Size)

	data, err := c.server.storage.Read(hdr.NodeID, int64(req.Offset), int64(req.Size))
	if err != nil {
		log.Printf("Client %d READ error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	resp := protocol.ReadResponse{
		Error: protocol.ErrNone,
		Data:  data,
	}

	log.Printf("Client %d READ result: %d bytes", c.id, len(data))
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleWrite(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d WRITE denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.WriteRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d WRITE decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d WRITE: ino=%d offset=%d size=%d", c.id, hdr.NodeID, req.Offset, len(req.Data))

	currentSize := c.server.storage.GetTotalSize()
	if currentSize+int64(len(req.Data)) > c.server.maxSize {
		log.Printf("Client %d WRITE error: no space", c.id)
		c.sendError(hdr, protocol.ErrNospc)
		return
	}

	written, newSize, err := c.server.storage.Write(hdr.NodeID, int64(req.Offset), req.Data)
	if err != nil {
		log.Printf("Client %d WRITE error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	resp := protocol.WriteResponse{
		Error:   protocol.ErrNone,
		Written: uint32(written),
		NewSize: uint64(newSize),
	}

	log.Printf("Client %d WRITE result: written=%d newsize=%d", c.id, written, newSize)
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleWatch(hdr *protocol.Header, payload []byte) {
	var req protocol.WatchRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d WATCH decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d WATCH: ino=%d events=0x%x", c.id, hdr.NodeID, req.Events)

	c.server.notify.Subscribe(c.id, hdr.NodeID, req.Events)

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleUnwatch(hdr *protocol.Header, payload []byte) {
	log.Printf("Client %d UNWATCH: ino=%d", c.id, hdr.NodeID)

	c.server.notify.Unsubscribe(c.id, hdr.NodeID)

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	c.sendResponse(hdr, &resp)
}

type encoder interface {
	Encode([]byte) int
}

func (c *Client) sendResponse(reqHdr *protocol.Header, resp encoder) {
	buf := make([]byte, protocol.MaxMsgSize)

	payloadLen := resp.Encode(buf[protocol.HeaderSize:])

	hdr := protocol.Header{
		Length: uint32(protocol.HeaderSize + payloadLen),
		Opcode: reqHdr.Opcode,
		Flags:  protocol.FlagResponse,
		TxnID:  reqHdr.TxnID,
		NodeID: reqHdr.NodeID,
	}
	hdr.Encode(buf)

	c.mu.Lock()
	n, err := c.conn.Write(buf[:hdr.Length])
	c.mu.Unlock()

	if err != nil {
		log.Printf("Client %d send response error: %v", c.id, err)
	} else {
		log.Printf("Client %d sent response: op=0x%02x len=%d", c.id, hdr.Opcode, n)
	}
}

func (c *Client) sendError(reqHdr *protocol.Header, errCode int32) {
	log.Printf("Client %d sending error: %d", c.id, errCode)
	resp := protocol.ErrorResponse{Error: errCode}
	c.sendResponse(reqHdr, &resp)
}

func (c *Client) Close() {
	close(c.quit)
	c.conn.Close()
}

func (c *Client) cleanup() {
	log.Printf("Client %d cleanup", c.id)
	c.server.notify.UnregisterClient(c.id)

	c.server.clientsMu.Lock()
	delete(c.server.clients, c.id)
	c.server.clientsMu.Unlock()
}

func (c *Client) handleTruncate(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d TRUNCATE denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.TruncateRequest
	if err := req.Decode(payload); err != nil {
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	log.Printf("Client %d TRUNCATE: ino=%d size=%d", c.id, hdr.NodeID, req.Size)

	if err := c.server.storage.Truncate(hdr.NodeID, int64(req.Size)); err != nil {
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	c.sendResponse(hdr, &resp)
}

func (c *Client) handleRename(hdr *protocol.Header, payload []byte) {
	if c.readOnly {
		log.Printf("Client %d RENAME denied (read-only)", c.id)
		c.sendError(hdr, protocol.ErrRofs)
		return
	}

	var req protocol.RenameRequest
	if err := req.Decode(payload); err != nil {
		log.Printf("Client %d RENAME decode error: %v", c.id, err)
		c.sendError(hdr, protocol.ErrProto)
		return
	}

	oldParent := hdr.NodeID
	newParent := req.NewParentIno
	oldName := req.OldName
	newName := req.NewName

	log.Printf("Client %d RENAME: oldParent=%d oldName=%q -> newParent=%d newName=%q",
		c.id, oldParent, oldName, newParent, newName)

	movedIno, err := c.server.storage.Rename(oldParent, oldName, newParent, newName)
	if err != nil {
		log.Printf("Client %d RENAME error: %v", c.id, err)
		c.sendError(hdr, storageErrToProto(err))
		return
	}

	// Notify watchers: treat rename as delete+create for now
	c.server.notify.NotifyDelete(oldParent, movedIno, oldName)
	c.server.notify.NotifyCreate(newParent, movedIno, newName)

	resp := protocol.ErrorResponse{Error: protocol.ErrNone}
	log.Printf("Client %d RENAME complete ino=%d", c.id, movedIno)
	c.sendResponse(hdr, &resp)
}

func storageErrToProto(err error) int32 {
	switch err {
	case storage.ErrNotFound:
		return protocol.ErrNoent
	case storage.ErrExists:
		return protocol.ErrExist
	case storage.ErrNotDir:
		return protocol.ErrNotdir
	case storage.ErrIsDir:
		return protocol.ErrIsdir
	case storage.ErrNotEmpty:
		return protocol.ErrNotempty
	case storage.ErrNoSpace:
		return protocol.ErrNospc
	case storage.ErrInvalidName:
		return protocol.ErrInval
	default:
		return protocol.ErrIO
	}
}

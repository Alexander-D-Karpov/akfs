package server

import (
	"sync"

	"github.com/Alexander-D-Karpov/akfs/backend/internal/protocol"
)

type Subscription struct {
	ClientID uint64
	DirIno   uint64
	Events   uint32
}

type NotifyManager struct {
	mu            sync.RWMutex
	subscriptions map[uint64]map[uint64]*Subscription
	clients       map[uint64]*Client
	nextSubID     uint64
}

func NewNotifyManager() *NotifyManager {
	return &NotifyManager{
		subscriptions: make(map[uint64]map[uint64]*Subscription),
		clients:       make(map[uint64]*Client),
	}
}

func (nm *NotifyManager) RegisterClient(client *Client) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	nm.clients[client.id] = client
}

func (nm *NotifyManager) UnregisterClient(clientID uint64) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	delete(nm.clients, clientID)

	for dirIno, subs := range nm.subscriptions {
		for subID, sub := range subs {
			if sub.ClientID == clientID {
				delete(subs, subID)
			}
		}
		if len(subs) == 0 {
			delete(nm.subscriptions, dirIno)
		}
	}
}

func (nm *NotifyManager) Subscribe(clientID uint64, dirIno uint64, events uint32) uint64 {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	nm.nextSubID++
	subID := nm.nextSubID

	sub := &Subscription{
		ClientID: clientID,
		DirIno:   dirIno,
		Events:   events,
	}

	if nm.subscriptions[dirIno] == nil {
		nm.subscriptions[dirIno] = make(map[uint64]*Subscription)
	}
	nm.subscriptions[dirIno][subID] = sub

	return subID
}

func (nm *NotifyManager) Unsubscribe(clientID uint64, dirIno uint64) {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	subs, ok := nm.subscriptions[dirIno]
	if !ok {
		return
	}

	for subID, sub := range subs {
		if sub.ClientID == clientID {
			delete(subs, subID)
		}
	}

	if len(subs) == 0 {
		delete(nm.subscriptions, dirIno)
	}
}

func (nm *NotifyManager) Notify(parentIno uint64, ino uint64, event uint32, name string) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	subs, ok := nm.subscriptions[parentIno]
	if !ok {
		return
	}

	ev := &protocol.NotifyEvent{
		ParentIno: parentIno,
		Ino:       ino,
		Event:     event,
		Name:      name,
	}

	notified := make(map[uint64]bool)

	for _, sub := range subs {
		if (sub.Events & event) == 0 {
			continue
		}

		if notified[sub.ClientID] {
			continue
		}

		client, ok := nm.clients[sub.ClientID]
		if !ok {
			continue
		}

		client.SendNotification(ev)
		notified[sub.ClientID] = true
	}
}

func (nm *NotifyManager) NotifyCreate(parentIno uint64, ino uint64, name string) {
	nm.Notify(parentIno, ino, protocol.NotifyCreate, name)
}

func (nm *NotifyManager) NotifyDelete(parentIno uint64, ino uint64, name string) {
	nm.Notify(parentIno, ino, protocol.NotifyDelete, name)
}

func (nm *NotifyManager) NotifyModify(parentIno uint64, ino uint64, name string) {
	nm.Notify(parentIno, ino, protocol.NotifyModify, name)
}

package storage

import (
	"container/list"
	"sync"
)

type CacheEntry struct {
	key     uint64
	value   []byte
	dirty   bool
	element *list.Element
}

type Cache struct {
	mu       sync.RWMutex
	capacity int
	items    map[uint64]*CacheEntry
	lru      *list.List
}

func NewCache(capacity int) *Cache {
	return &Cache{
		capacity: capacity,
		items:    make(map[uint64]*CacheEntry),
		lru:      list.New(),
	}
}

func (c *Cache) Get(key uint64) ([]byte, bool) {
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	c.mu.Lock()
	c.lru.MoveToFront(entry.element)
	c.mu.Unlock()

	return entry.value, true
}

func (c *Cache) Put(key uint64, value []byte, dirty bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		entry.value = value
		entry.dirty = entry.dirty || dirty
		c.lru.MoveToFront(entry.element)
		return
	}

	if c.lru.Len() >= c.capacity {
		c.evict()
	}

	entry := &CacheEntry{
		key:   key,
		value: value,
		dirty: dirty,
	}
	entry.element = c.lru.PushFront(entry)
	c.items[key] = entry
}

func (c *Cache) evict() {
	elem := c.lru.Back()
	if elem == nil {
		return
	}

	entry := elem.Value.(*CacheEntry)
	c.lru.Remove(elem)
	delete(c.items, entry.key)
}

func (c *Cache) Invalidate(key uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		c.lru.Remove(entry.element)
		delete(c.items, key)
	}
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[uint64]*CacheEntry)
	c.lru.Init()
}

func (c *Cache) GetDirty() []uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var keys []uint64
	for key, entry := range c.items {
		if entry.dirty {
			keys = append(keys, key)
		}
	}
	return keys
}

func (c *Cache) MarkClean(key uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, ok := c.items[key]; ok {
		entry.dirty = false
	}
}

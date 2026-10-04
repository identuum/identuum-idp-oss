package service

import "sync"

// keyedMutex serializes work per key. An entry exists only while someone holds
// or awaits its key, so the map stays as small as the work in flight. The zero
// value is ready to use.
type keyedMutex struct {
	mu      sync.Mutex
	entries map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	mu   sync.Mutex
	refs int
}

// lock blocks until key is free, takes it, and returns the function that
// releases it.
func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	if k.entries == nil {
		k.entries = make(map[string]*keyedMutexEntry)
	}
	e := k.entries[key]
	if e == nil {
		e = &keyedMutexEntry{}
		k.entries[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()
	return func() {
		e.mu.Unlock()
		k.mu.Lock()
		e.refs--
		if e.refs == 0 {
			delete(k.entries, key)
		}
		k.mu.Unlock()
	}
}

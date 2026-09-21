// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package daemon

import "sync"

// hookTable backs app-facing Register* APIs. The map is created on first put
// and is not a field New() can replace with a fresh empty map.
type hookTable[T any] struct {
	mu sync.RWMutex
	m  map[string]T
}

func (t *hookTable[T]) put(key string, fn T) {
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = make(map[string]T)
	}
	t.m[key] = fn
}

func (t *hookTable[T]) delete(key string) {
	if key == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, key)
}

func (t *hookTable[T]) get(key string) T {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.m[key]
}

func (t *hookTable[T]) len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.m)
}

func (t *hookTable[T]) clone() map[string]T {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.m) == 0 {
		return nil
	}
	out := make(map[string]T, len(t.m))
	for k, v := range t.m {
		out[k] = v
	}
	return out
}

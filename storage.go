// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package a2al

import (
	"sync"
)

// Storage is a key-value persistence abstraction. Implementations live in the
// application layer (desktop path, mobile sandbox, etc.).
type Storage interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}

// MemStorage is an in-memory Storage for tests and ephemeral use.
type MemStorage struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemStorage returns an empty MemStorage.
func NewMemStorage() *MemStorage {
	return &MemStorage{m: make(map[string][]byte)}
}

func (s *MemStorage) Get(key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (s *MemStorage) Put(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	s.m[key] = cp
	return nil
}

func (s *MemStorage) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

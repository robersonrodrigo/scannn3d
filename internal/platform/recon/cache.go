package recon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type cacheEntry struct {
	ResultJSON []byte    `json:"result_json"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Cache struct {
	mu      sync.Mutex
	path    string
	entries map[string]cacheEntry
}

func NewCache(dsn string) (*Cache, error) {
	if dsn == "" {
		dsn = "platform-runs/recon-cache.json"
	}
	c := &Cache{path: dsn, entries: map[string]cacheEntry{}}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func cacheKey(module, inputHash string) string {
	return module + ":" + inputHash
}

func (c *Cache) Get(_ context.Context, module, inputHash string) ([]byte, bool, error) {
	if c == nil {
		return nil, false, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := cacheKey(module, inputHash)
	e, ok := c.entries[k]
	if !ok {
		return nil, false, nil
	}
	if time.Now().UTC().After(e.ExpiresAt) {
		delete(c.entries, k)
		_ = c.persist()
		return nil, false, nil
	}
	return append([]byte(nil), e.ResultJSON...), true, nil
}

func (c *Cache) Set(_ context.Context, module, inputHash string, data []byte, ttl time.Duration) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now().UTC()
	c.entries[cacheKey(module, inputHash)] = cacheEntry{
		ResultJSON: append([]byte(nil), data...),
		CreatedAt:  now,
		ExpiresAt:  now.Add(ttl),
	}
	return c.persist()
}

func (c *Cache) Close() error { return nil }

func (c *Cache) load() error {
	if c.path == "" {
		return nil
	}
	b, err := os.ReadFile(c.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, &c.entries)
}

func (c *Cache) persist() error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o750); err != nil {
		return err
	}
	b, err := json.Marshal(c.entries)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, b, 0o640)
}

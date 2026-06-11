// Package contain implements the filesystem reversibility / containment engine
// (AW-Spec v0.2 §3.2). It uses the portable Tier-C userspace journal (copy-before-
// write of touched paths) so reversible-destructive filesystem operations can run
// freely and be rolled back. Reflink/OS snapshots (Tier A/B) are a later
// optimization (P1-HLD §5.1).
//
// Licensed under the Apache License 2.0.
package contain

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type entry struct {
	path          string // absolute target path
	existedBefore bool
	backupPath    string // copy of prior content, if existedBefore
}

// Journal contains filesystem effects within a working tree.
type Journal struct {
	mu       sync.Mutex
	worktree string // absolute; only paths inside are reversible (declared scope)
	store    string // absolute; snapshot store (under trust root)
	entries  []entry
	seq      int
}

// NewJournal creates a journal for worktree, storing snapshots under store.
func NewJournal(worktree, store string) (*Journal, error) {
	wt, err := filepath.Abs(worktree)
	if err != nil {
		return nil, err
	}
	st, err := filepath.Abs(store)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(st, 0o700); err != nil {
		return nil, err
	}
	return &Journal{worktree: wt, store: st}, nil
}

// InScope reports whether path is inside the worktree (declared reversibility
// scope, AW-Spec §3.2). Effects outside scope are NOT reversible and the broker
// routes them to the gate as I-DESTROY.
func (j *Journal) InScope(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(j.worktree, abs)
	if err != nil {
		return false
	}
	return rel != ".." && !startsWithDotDot(rel)
}

func startsWithDotDot(rel string) bool {
	return len(rel) >= 2 && rel[0] == '.' && rel[1] == '.'
}

// snapshot records the pre-state of path so it can be restored. Must be called
// before any reversible-destructive operation (AW-Spec §3.2).
func (j *Journal) snapshot(abs string) error {
	e := entry{path: abs}
	data, err := os.ReadFile(abs)
	if err != nil {
		if os.IsNotExist(err) {
			e.existedBefore = false
			j.entries = append(j.entries, e)
			return nil
		}
		return err
	}
	e.existedBefore = true
	e.backupPath = filepath.Join(j.store, fmt.Sprintf("snap-%06d.bak", j.seq))
	j.seq++
	if err := os.WriteFile(e.backupPath, data, 0o600); err != nil {
		return err
	}
	j.entries = append(j.entries, e)
	return nil
}

// Write snapshots then writes content to path. Returns an error if path is out of
// scope (the caller should have gated it instead).
func (j *Journal) Write(path string, content []byte) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	abs, _ := filepath.Abs(path)
	if !j.InScope(abs) {
		return fmt.Errorf("out of reversible scope: %s", path)
	}
	if err := j.snapshot(abs); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	return os.WriteFile(abs, content, 0o644)
}

// Delete snapshots then removes path (reversible-destructive).
func (j *Journal) Delete(path string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	abs, _ := filepath.Abs(path)
	if !j.InScope(abs) {
		return fmt.Errorf("out of reversible scope: %s", path)
	}
	if err := j.snapshot(abs); err != nil {
		return err
	}
	err := os.Remove(abs)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Rollback restores the worktree to its pre-journal state by replaying entries in
// reverse (AW-Spec §3.2). After rollback the journal is empty.
func (j *Journal) Rollback() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	for i := len(j.entries) - 1; i >= 0; i-- {
		e := j.entries[i]
		if e.existedBefore {
			data, err := os.ReadFile(e.backupPath)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(e.path), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(e.path, data, 0o644); err != nil {
				return err
			}
		} else {
			// Created during the session: remove it.
			if err := os.Remove(e.path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	j.entries = nil
	return nil
}

// Count returns the number of journaled operations (for tests / reach views).
func (j *Journal) Count() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.entries)
}

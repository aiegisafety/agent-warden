// Package ledger implements the append-only, SHA-256 hash-chained, independently
// verifiable audit log (AW-Spec v0.2 §8). The verify path (Verify) needs no trust
// in the broker process — it recomputes the chain from genesis: verify-over-trust.
//
// Licensed under the Apache License 2.0.
package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/aiegis/agentwarden/pkg/awspec"
)

// genesisConstant is the documented fixed seed the first record commits to
// (AW-Spec §8.1). Changing it breaks all historical verification by design.
const genesisConstant = "AW-LEDGER-GENESIS-v0.2"

// RecordType enumerates the ledger record kinds (AW-Spec §8.2).
type RecordType string

const (
	GateDecision      RecordType = "gate_decision"
	IrreversibleEffect RecordType = "irreversible_effect"
	ReachChange       RecordType = "reach_change"
	PolicyEvent       RecordType = "policy_event"
	Override          RecordType = "override"
)

// Body holds the hashed content of a record. Field order is fixed; encoding/json
// marshals struct fields in declaration order and map keys sorted, giving a
// deterministic canonical encoding (AW-Spec §8.2 canonical bytes).
type Body struct {
	Seq            uint64               `json:"seq"`
	TS             string               `json:"ts"`
	HashAlg        string               `json:"hash_alg"` // agility (AW-Spec §8.3)
	RecordType     RecordType           `json:"record_type"`
	AgentID        string               `json:"agent_id"`
	Substrate      awspec.Substrate     `json:"substrate"`
	ActionClass    string               `json:"action_class"`
	IrrevCategory  awspec.IrrevCategory `json:"irrev_category"`
	Verdict        awspec.Verdict       `json:"verdict"`
	Simulated      bool                 `json:"simulated"` // AW-G-1: true iff decoy-routed
	CapabilityRef  string               `json:"capability_ref"`
	LifecycleState awspec.LifecycleState `json:"lifecycle_state"`
	Taint          string               `json:"taint"`
	EffectDigest   string               `json:"effect_digest"`

	// Integration provenance (AW-INT-v0.1 §1.4). omitempty keeps the canonical
	// bytes — and therefore every historical chain_hash — unchanged for records
	// written by Tier-0 paths that leave these zero.
	Source string `json:"source,omitempty"`
	Tier   int    `json:"tier,omitempty"`
	Tool   string `json:"tool,omitempty"`
}

// Record is a Body plus the chain linkage (AW-Spec §8.1).
type Record struct {
	Body      Body   `json:"body"`
	PrevHash  string `json:"prev_hash"`
	ChainHash string `json:"chain_hash"`
}

// canonicalBytes returns the deterministic encoding of a Body used for hashing.
func canonicalBytes(b Body) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(b); err != nil {
		return nil, err
	}
	// json.Encoder appends a trailing newline; trim it so encoding is stable.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// computeChainHash implements chain_hash = SHA256( prevHash || canonical(body) )
// (AW-Spec §8.1). prevHash is the hex string of the prior record's chain hash.
func computeChainHash(prevHash string, b Body) (string, error) {
	cb, err := canonicalBytes(b)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(cb)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// genesisHash is the prev_hash of the very first record.
func genesisHash() string {
	sum := sha256.Sum256([]byte(genesisConstant))
	return hex.EncodeToString(sum[:])
}

// Ledger is an append-only hash-chained log persisted to a file.
type Ledger struct {
	mu       sync.Mutex
	path     string
	nextSeq  uint64
	headHash string
}

// Open opens (or creates) a ledger at path, scanning any existing records to
// recover the head hash and next sequence number.
func Open(path string) (*Ledger, error) {
	l := &Ledger{path: path, nextSeq: 0, headHash: genesisHash()}
	recs, err := readAll(path)
	if err != nil {
		return nil, err
	}
	if len(recs) > 0 {
		last := recs[len(recs)-1]
		l.nextSeq = last.Body.Seq + 1
		l.headHash = last.ChainHash
	}
	return l, nil
}

// Append writes a new record committing to the current head, then advances head.
// The Seq, TS, HashAlg, PrevHash and ChainHash fields are filled here; callers
// supply the rest of the Body.
func (l *Ledger) Append(b Body) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	b.Seq = l.nextSeq
	b.TS = time.Now().UTC().Format(time.RFC3339Nano)
	b.HashAlg = "sha256"

	prev := l.headHash
	ch, err := computeChainHash(prev, b)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Body: b, PrevHash: prev, ChainHash: ch}

	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Record{}, err
	}
	if err := f.Sync(); err != nil { // durable before effect release (AW-Spec §3.3)
		return Record{}, err
	}

	l.nextSeq++
	l.headHash = ch
	return rec, nil
}

// readAll loads every record from a ledger file. A missing file is not an error.
func readAll(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("malformed ledger line: %w", err)
		}
		recs = append(recs, r)
	}
	return recs, sc.Err()
}

// VerifyResult reports the outcome of a chain verification.
type VerifyResult struct {
	OK       bool
	Count    int
	BadSeq   int64  // first offending seq, or -1 if OK
	Detail   string
}

// Verify recomputes the hash chain from genesis and checks every record. It needs
// no trust in the writer (verify-over-trust, AW-Spec §5.3, §8.1). Any mismatch is
// localized to the first offending record's seq.
func Verify(path string) (VerifyResult, error) {
	recs, err := readAll(path)
	if err != nil {
		return VerifyResult{OK: false, BadSeq: -1, Detail: err.Error()}, err
	}
	prev := genesisHash()
	for i, r := range recs {
		// sequence must be contiguous from 0
		if r.Body.Seq != uint64(i) {
			return VerifyResult{OK: false, Count: len(recs), BadSeq: int64(i),
				Detail: fmt.Sprintf("seq gap: record %d has seq %d", i, r.Body.Seq)}, nil
		}
		if r.PrevHash != prev {
			return VerifyResult{OK: false, Count: len(recs), BadSeq: int64(r.Body.Seq),
				Detail: fmt.Sprintf("prev_hash mismatch at seq %d", r.Body.Seq)}, nil
		}
		want, err := computeChainHash(prev, r.Body)
		if err != nil {
			return VerifyResult{OK: false, BadSeq: int64(r.Body.Seq), Detail: err.Error()}, err
		}
		if want != r.ChainHash {
			return VerifyResult{OK: false, Count: len(recs), BadSeq: int64(r.Body.Seq),
				Detail: fmt.Sprintf("chain_hash mismatch at seq %d (record body tampered)", r.Body.Seq)}, nil
		}
		prev = r.ChainHash
	}
	return VerifyResult{OK: true, Count: len(recs), BadSeq: -1, Detail: "chain intact"}, nil
}

// ReadAll exposes the parsed records (for audit / reach views).
func ReadAll(path string) ([]Record, error) { return readAll(path) }

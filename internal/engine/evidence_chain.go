package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/yxshwanth/Interlock/internal/model"
)

// HashEvidenceRecord returns the hex-encoded SHA-256 of rec with Hash cleared.
// Encoding matches HashValue (lowercase 64-char hex). Go's encoding/json sorts
// map keys, so SinkCall map[string]any serializes deterministically.
func HashEvidenceRecord(rec model.EvidenceRecord) (string, error) {
	rec.Hash = ""
	data, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("marshaling evidence for hash: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// SealEvidenceRecord sets ChainSeq, PrevHash, and Hash on rec for the next
// position in the chain. prevHash is empty for the genesis record (seq 0).
func SealEvidenceRecord(rec *model.EvidenceRecord, seq uint64, prevHash string) error {
	rec.ChainSeq = seq
	rec.PrevHash = prevHash
	rec.Hash = ""
	h, err := HashEvidenceRecord(*rec)
	if err != nil {
		return err
	}
	rec.Hash = h
	return nil
}

// ChainBreak describes where VerifyChain found a problem.
type ChainBreak struct {
	Index  int    // 0-based index into the records slice
	Reason string // "hash mismatch" | "chain link broken" | "seq mismatch"
}

func (b ChainBreak) Error() string {
	return fmt.Sprintf("evidence chain broken at record %d: %s", b.Index, b.Reason)
}

// VerifyChain checks that records form a contiguous hash chain.
// The first record may be genesis (ChainSeq 0, PrevHash "") or the tip of a
// pruned/rotated head (ChainSeq > 0) — SQLite max_records prune deletes the
// oldest rows, so verification of what remains still detects mid-chain
// edit/delete. An empty slice is valid (vacuously).
func VerifyChain(records []model.EvidenceRecord) error {
	for i, rec := range records {
		if i == 0 {
			if rec.ChainSeq == 0 && rec.PrevHash != "" {
				return &ChainBreak{Index: i, Reason: "chain link broken"}
			}
		} else {
			prev := records[i-1]
			if rec.ChainSeq != prev.ChainSeq+1 {
				return &ChainBreak{Index: i, Reason: fmt.Sprintf("seq mismatch: got %d want %d", rec.ChainSeq, prev.ChainSeq+1)}
			}
			if rec.PrevHash != prev.Hash {
				return &ChainBreak{Index: i, Reason: "chain link broken"}
			}
		}
		stored := rec.Hash
		got, err := HashEvidenceRecord(rec)
		if err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if stored == "" || stored != got {
			return &ChainBreak{Index: i, Reason: "hash mismatch"}
		}
	}
	return nil
}

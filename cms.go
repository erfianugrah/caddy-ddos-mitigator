// Package ddosmitigator — Count-Min Sketch subsystem.
//
// Probabilistic frequency counter using a d×w matrix of atomic int64 counters.
// Provides O(d) Increment/Estimate with bounded overestimation and zero lock
// contention (all updates via atomic.Int64).
//
// Memory: d * w * 8 bytes (default 4 * 8192 = 256KB fixed).
// Error bound: ε ≈ 1/w with probability ≈ 1 - (1/e)^d.
package ddosmitigator

import (
	"crypto/rand"
	"encoding/binary"
	"hash/fnv"
	"math"
	"sync/atomic"
)

// ─── Types ──────────────────────────────────────────────────────────

// countMinSketch is a probabilistic frequency counter.
type countMinSketch struct {
	depth  int
	width  int
	matrix [][]atomic.Int64
	seeds  []uint64
}

// ─── Constructor ────────────────────────────────────────────────────

// newCountMinSketch creates a CMS with the given depth (hash functions)
// and width (counters per row). Typical: depth=4, width=8192.
func newCountMinSketch(depth, width int) *countMinSketch {
	cms := &countMinSketch{
		depth:  depth,
		width:  width,
		matrix: make([][]atomic.Int64, depth),
		seeds:  make([]uint64, depth),
	}
	for i := range depth {
		cms.matrix[i] = make([]atomic.Int64, width)
		// Cryptographically random seeds for independent hash functions.
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		cms.seeds[i] = binary.LittleEndian.Uint64(buf[:])
	}
	return cms
}

// ─── Hash ───────────────────────────────────────────────────────────

// hash computes the column index for the given key in the specified row.
// Uses FNV-64a seeded by XOR with the per-row seed.
func (cms *countMinSketch) hash(row int, key []byte) int {
	h := fnv.New64a()
	// Seed by writing the per-row seed as a prefix.
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], cms.seeds[row])
	h.Write(buf[:])
	h.Write(key)
	return int(h.Sum64() % uint64(cms.width))
}

// ─── Operations ─────────────────────────────────────────────────────

// Increment atomically increments all counters for the given key and
// returns the minimum count (the frequency estimate).
func (cms *countMinSketch) Increment(key []byte) int64 {
	minVal := int64(math.MaxInt64)
	for i := range cms.depth {
		col := cms.hash(i, key)
		newVal := cms.matrix[i][col].Add(1)
		if newVal < minVal {
			minVal = newVal
		}
	}
	return minVal
}

// Estimate returns the estimated frequency for the given key.
// Guarantee: Estimate(key) >= true frequency. May overestimate due to
// hash collisions, bounded by the CMS error parameters.
func (cms *countMinSketch) Estimate(key []byte) int64 {
	minVal := int64(math.MaxInt64)
	for i := range cms.depth {
		col := cms.hash(i, key)
		val := cms.matrix[i][col].Load()
		if val < minVal {
			minVal = val
		}
	}
	if minVal == math.MaxInt64 {
		return 0
	}
	return minVal
}

// Decay multiplies all counters by the given factor (0 < factor < 1).
// Used for exponential decay of stale fingerprints. Called by a background
// goroutine, not on the hot path.
func (cms *countMinSketch) Decay(factor float64) {
	for i := range cms.depth {
		for j := range cms.width {
			for {
				old := cms.matrix[i][j].Load()
				if old <= 0 {
					break
				}
				newVal := int64(float64(old) * factor)
				if cms.matrix[i][j].CompareAndSwap(old, newVal) {
					break
				}
			}
		}
	}
}

// Reset zeroes all counters.
func (cms *countMinSketch) Reset() {
	for i := range cms.depth {
		for j := range cms.width {
			cms.matrix[i][j].Store(0)
		}
	}
}

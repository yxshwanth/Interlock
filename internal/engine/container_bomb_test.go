package engine

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"runtime"
	"testing"
	"time"
)

// gzipBomb builds a small high-ratio gzip: zeros compress tiny but expand huge.
func gzipBomb(expanded int) []byte {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	// Write in chunks so we don't allocate the full expanded slice in the fixture.
	chunk := bytes.Repeat([]byte{0}, 64<<10)
	left := expanded
	for left > 0 {
		n := left
		if n > len(chunk) {
			n = len(chunk)
		}
		if _, err := gw.Write(chunk[:n]); err != nil {
			panic(err)
		}
		left -= n
	}
	if err := gw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// nestZIP wraps raw as a single-member ZIP named name.
func nestZIP(name string, raw []byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		panic(err)
	}
	if _, err := w.Write(raw); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// TestInspectContainer_GzipBomb_Survives is the §20 TCB pin: a high-ratio
// gzip must abort mid-decompress with max_decompressed_bytes, stay within a
// memory ceiling proportional to the cap (not the expanded size), and finish
// in bounded wall time — not after a stall/OOM.
func TestInspectContainer_GzipBomb_Survives(t *testing.T) {
	const (
		expanded = 32 << 20 // 32 MiB of zeros → tiny gzip, huge expand
		capBytes = 64 << 10 // 64 KiB hard cap
	)
	bomb := gzipBomb(expanded)
	if len(bomb) > 256<<10 {
		t.Fatalf("fixture not bomb-shaped: compressed=%d (want << expanded)", len(bomb))
	}
	lim := DefaultContainerLimits()
	lim.MaxDecompressedBytes = capBytes
	lim.MaxInspect = 2 * time.Second

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	start := time.Now()
	res := InspectContainer(bomb, lim)
	elapsed := time.Since(start)

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc

	if res.Abort != ContainerAbortMaxBytes {
		t.Fatalf("abort = %q, want %q", res.Abort, ContainerAbortMaxBytes)
	}
	// Peak alloc must be O(cap), not O(expanded). Allow headroom for gzip
	// tables, test harness, and the chunk buffer.
	const memCeiling = capBytes*8 + 2<<20
	if alloc > uint64(memCeiling) {
		t.Fatalf("alloc delta %d exceeds ceiling %d (cap=%d expanded=%d) — bomb escaped budget",
			alloc, memCeiling, capBytes, expanded)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("elapsed %v exceeds 500ms — bomb stalled the inspector", elapsed)
	}
	t.Logf("gzip bomb: compressed=%d expanded=%d abort=%s alloc=%d elapsed=%v",
		len(bomb), expanded, res.Abort, alloc, elapsed)
}

// TestInspectContainer_NestedZipDepth_Survives pins depth abort before a third
// layer is walked, with bounded time on a nest that would otherwise expand.
func TestInspectContainer_NestedZipDepth_Survives(t *testing.T) {
	// zip(zip(zip(gzipBomb))) — depth cap 2 must abort before opening layer 3.
	inner := nestZIP("bomb.gz", gzipBomb(8<<20))
	mid := nestZIP("inner.zip", inner)
	outer := nestZIP("mid.zip", mid)

	lim := DefaultContainerLimits()
	lim.MaxDescentDepth = 2
	lim.MaxDecompressedBytes = 4 << 20
	lim.MaxInspect = 2 * time.Second

	start := time.Now()
	res := InspectContainer(outer, lim)
	elapsed := time.Since(start)

	if res.Abort != ContainerAbortMaxDepth && res.Abort != ContainerAbortMaxBytes {
		t.Fatalf("abort = %q, want max_descent_depth or max_decompressed_bytes", res.Abort)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("elapsed %v exceeds 500ms", elapsed)
	}
	t.Logf("nested zip: size=%d abort=%s elapsed=%v", len(outer), res.Abort, elapsed)
}

// TestInspectContainer_ZipMemberBomb_Survives: a ZIP member whose deflated
// zeros expand past the byte cap — classic archive bomb shape.
func TestInspectContainer_ZipMemberBomb_Survives(t *testing.T) {
	const (
		expanded = 16 << 20
		capBytes = 32 << 10
	)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("zeros.bin")
	if err != nil {
		t.Fatal(err)
	}
	chunk := bytes.Repeat([]byte{0}, 64<<10)
	left := expanded
	for left > 0 {
		n := left
		if n > len(chunk) {
			n = len(chunk)
		}
		if _, err := w.Write(chunk[:n]); err != nil {
			t.Fatal(err)
		}
		left -= n
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()

	lim := DefaultContainerLimits()
	lim.MaxDecompressedBytes = capBytes
	lim.MaxInspect = 2 * time.Second

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	res := InspectContainer(raw, lim)
	elapsed := time.Since(start)
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	alloc := after.TotalAlloc - before.TotalAlloc

	if res.Abort != ContainerAbortMaxBytes {
		t.Fatalf("abort = %q, want %q", res.Abort, ContainerAbortMaxBytes)
	}
	const memCeiling = capBytes*8 + 4<<20 // zip may buffer compressed member
	if alloc > uint64(memCeiling) {
		t.Fatalf("alloc delta %d exceeds ceiling %d", alloc, memCeiling)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("elapsed %v exceeds 500ms", elapsed)
	}
	t.Logf("zip member bomb: zip=%d abort=%s alloc=%d elapsed=%v", len(raw), res.Abort, alloc, elapsed)
}

func TestInspectContainer_TimeBudget_HardAbort(t *testing.T) {
	bomb := gzipBomb(8 << 20)
	lim := DefaultContainerLimits()
	lim.MaxDecompressedBytes = 8 << 20 // large enough that time should win first
	lim.MaxInspect = time.Microsecond

	start := time.Now()
	res := InspectContainer(bomb, lim)
	elapsed := time.Since(start)

	if res.Abort != ContainerAbortMaxTime && res.Abort != ContainerAbortMaxBytes {
		t.Fatalf("abort = %q, want max_inspect_ms or max_decompressed_bytes", res.Abort)
	}
	if elapsed > 200*time.Millisecond {
		t.Fatalf("elapsed %v — time budget did not bound the walk", elapsed)
	}
}

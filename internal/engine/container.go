package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// ContainerAbortReason names why InspectContainer stopped early.
type ContainerAbortReason string

const (
	ContainerAbortNone          ContainerAbortReason = ""
	ContainerAbortMaxBytes      ContainerAbortReason = "max_decompressed_bytes"
	ContainerAbortMaxDepth      ContainerAbortReason = "max_descent_depth"
	ContainerAbortMaxParts      ContainerAbortReason = "max_parts"
	ContainerAbortMaxTime       ContainerAbortReason = "max_inspect_ms"
	ContainerAbortEncrypted     ContainerAbortReason = "encrypted"
	ContainerAbortCorrupt       ContainerAbortReason = "corrupt"
)

// ContainerLimits are hard caps for one InspectContainer walk (ROADMAP §20).
type ContainerLimits struct {
	Enabled              bool
	MaxDecompressedBytes int
	MaxDescentDepth      int
	MaxParts             int
	MaxInspect           time.Duration
}

// DefaultContainerLimits returns production defaults.
func DefaultContainerLimits() ContainerLimits {
	return ContainerLimits{
		Enabled:              true,
		MaxDecompressedBytes: 10 * 1024 * 1024,
		MaxDescentDepth:      2,
		MaxParts:             100,
		MaxInspect:           50 * time.Millisecond,
	}
}

// ContainerInspectResult is the output of a bounded container walk.
type ContainerInspectResult struct {
	Parts  []string
	Abort  ContainerAbortReason
	Bytes  int // cumulative decompressed bytes attributed to this walk
	PartsN int
}

type containerWalker struct {
	lim      ContainerLimits
	deadline time.Time
	bytes    int
	parts    int
	out      []string
	abort    ContainerAbortReason
}

// LooksLikeContainer reports whether raw starts with a recognized container magic.
func LooksLikeContainer(raw []byte) bool {
	return detectContainerKind(raw) != containerKindNone
}

type containerKind int

const (
	containerKindNone containerKind = iota
	containerKindZIP
	containerKindGzip
	containerKindZlib
	containerKindTar
)

func detectContainerKind(raw []byte) containerKind {
	if len(raw) >= 4 && raw[0] == 'P' && raw[1] == 'K' && raw[2] == 0x03 && raw[3] == 0x04 {
		return containerKindZIP
	}
	if len(raw) >= 2 && raw[0] == 0x1f && raw[1] == 0x8b {
		return containerKindGzip
	}
	if len(raw) >= 2 && raw[0] == 0x78 && (raw[1] == 0x01 || raw[1] == 0x9c || raw[1] == 0xda) {
		return containerKindZlib
	}
	if looksLikeTar(raw) {
		return containerKindTar
	}
	return containerKindNone
}

func looksLikeTar(raw []byte) bool {
	if len(raw) < 512 {
		return false
	}
	// POSIX ustar magic at offset 257.
	if len(raw) >= 262 && string(raw[257:262]) == "ustar" {
		return true
	}
	return false
}

// InspectContainer walks a recognized container under lim and returns text
// parts suitable for secret extraction / overlap. On any limit hit, Abort is
// set and Parts may be partial; callers must not treat abort as EXFIL proof.
func InspectContainer(raw []byte, lim ContainerLimits) ContainerInspectResult {
	if !lim.Enabled || len(raw) == 0 || detectContainerKind(raw) == containerKindNone {
		return ContainerInspectResult{}
	}
	if lim.MaxDecompressedBytes <= 0 {
		lim.MaxDecompressedBytes = DefaultContainerLimits().MaxDecompressedBytes
	}
	if lim.MaxDescentDepth <= 0 {
		lim.MaxDescentDepth = DefaultContainerLimits().MaxDescentDepth
	}
	if lim.MaxParts <= 0 {
		lim.MaxParts = DefaultContainerLimits().MaxParts
	}
	if lim.MaxInspect <= 0 {
		lim.MaxInspect = DefaultContainerLimits().MaxInspect
	}

	w := &containerWalker{
		lim:      lim,
		deadline: time.Now().Add(lim.MaxInspect),
	}
	w.walk(raw, 0)
	return ContainerInspectResult{
		Parts:  w.out,
		Abort:  w.abort,
		Bytes:  w.bytes,
		PartsN: w.parts,
	}
}

func (w *containerWalker) timedOut() bool {
	return time.Now().After(w.deadline)
}

func (w *containerWalker) setAbort(r ContainerAbortReason) {
	if w.abort == ContainerAbortNone {
		w.abort = r
	}
}

func (w *containerWalker) walk(raw []byte, depth int) {
	if w.abort != ContainerAbortNone {
		return
	}
	if w.timedOut() {
		w.setAbort(ContainerAbortMaxTime)
		return
	}
	if depth > w.lim.MaxDescentDepth {
		w.setAbort(ContainerAbortMaxDepth)
		return
	}
	switch detectContainerKind(raw) {
	case containerKindZIP:
		w.walkZIP(raw, depth)
	case containerKindGzip:
		w.walkGzip(raw, depth)
	case containerKindZlib:
		w.walkZlib(raw, depth)
	case containerKindTar:
		w.walkTar(raw, depth)
	default:
		w.considerText(raw)
	}
}

func (w *containerWalker) addBytes(n int) bool {
	w.bytes += n
	if w.bytes > w.lim.MaxDecompressedBytes {
		w.setAbort(ContainerAbortMaxBytes)
		return false
	}
	return true
}

func (w *containerWalker) addPart() bool {
	w.parts++
	if w.parts > w.lim.MaxParts {
		w.setAbort(ContainerAbortMaxParts)
		return false
	}
	return true
}

func (w *containerWalker) considerText(b []byte) {
	if w.abort != ContainerAbortNone || len(b) == 0 {
		return
	}
	if !w.addBytes(len(b)) {
		return
	}
	if !isMostlyPrintable(b) {
		return
	}
	s := string(b)
	if strings.TrimSpace(s) == "" {
		return
	}
	w.out = append(w.out, s)
}

func (w *containerWalker) considerMember(b []byte, depth int) {
	if w.abort != ContainerAbortNone || len(b) == 0 {
		return
	}
	if !w.addBytes(len(b)) {
		return
	}
	if !w.addPart() {
		return
	}
	if w.timedOut() {
		w.setAbort(ContainerAbortMaxTime)
		return
	}
	if detectContainerKind(b) != containerKindNone {
		if depth+1 > w.lim.MaxDescentDepth {
			w.setAbort(ContainerAbortMaxDepth)
			return
		}
		w.walk(b, depth+1)
		return
	}
	if !isMostlyPrintable(b) {
		return
	}
	s := string(b)
	if strings.TrimSpace(s) == "" {
		return
	}
	w.out = append(w.out, s)
}

// readChunk is the per-read decompress buffer. Caps peak working set to one
// chunk plus the accumulated member (itself capped by remain).
const readChunk = 32 << 10

// readCapped copies from r until EOF or remain bytes, checking the time budget
// between chunks. remain should be MaxDecompressedBytes-bytes+1 so filling it
// proves more output exists. On fill, sets max_decompressed_bytes and returns
// overrun=true — caller must not treat data as a complete member.
func (w *containerWalker) readCapped(r io.Reader, remain int) (data []byte, overrun bool) {
	if remain <= 0 {
		w.setAbort(ContainerAbortMaxBytes)
		return nil, true
	}
	buf := make([]byte, 0, min(remain, readChunk))
	tmp := make([]byte, readChunk)
	for len(buf) < remain {
		if w.timedOut() {
			w.setAbort(ContainerAbortMaxTime)
			return nil, false
		}
		want := remain - len(buf)
		if want > readChunk {
			want = readChunk
		}
		n, err := r.Read(tmp[:want])
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err == io.EOF {
			return buf, false
		}
		if err != nil {
			w.setAbort(ContainerAbortCorrupt)
			return nil, false
		}
		if n == 0 {
			w.setAbort(ContainerAbortCorrupt)
			return nil, false
		}
	}
	w.setAbort(ContainerAbortMaxBytes)
	return buf, true
}

func (w *containerWalker) remainBudget() int {
	return w.lim.MaxDecompressedBytes - w.bytes + 1
}

func (w *containerWalker) walkZIP(raw []byte, depth int) {
	// ponytail: zip.NewReader materializes the central directory before MaxParts
	// can stop iteration — upgrade to streaming ZIP if CD DoS shows up in corpus.
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		w.setAbort(ContainerAbortCorrupt)
		return
	}
	for _, f := range zr.File {
		if w.abort != ContainerAbortNone {
			return
		}
		if w.timedOut() {
			w.setAbort(ContainerAbortMaxTime)
			return
		}
		if f.Flags&0x1 != 0 {
			w.setAbort(ContainerAbortEncrypted)
			return
		}
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			w.setAbort(ContainerAbortCorrupt)
			return
		}
		data, overrun := w.readCapped(rc, w.remainBudget())
		_ = rc.Close()
		if w.abort != ContainerAbortNone {
			return
		}
		if overrun {
			return
		}
		w.considerMember(data, depth)
	}
}

func (w *containerWalker) walkGzip(raw []byte, depth int) {
	gr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		w.setAbort(ContainerAbortCorrupt)
		return
	}
	defer gr.Close()
	data, overrun := w.readCapped(gr, w.remainBudget())
	if w.abort != ContainerAbortNone || overrun {
		return
	}
	w.considerMember(data, depth)
}

func (w *containerWalker) walkZlib(raw []byte, depth int) {
	zr, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		w.setAbort(ContainerAbortCorrupt)
		return
	}
	defer zr.Close()
	data, overrun := w.readCapped(zr, w.remainBudget())
	if w.abort != ContainerAbortNone || overrun {
		return
	}
	w.considerMember(data, depth)
}

func (w *containerWalker) walkTar(raw []byte, depth int) {
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		if w.abort != ContainerAbortNone {
			return
		}
		if w.timedOut() {
			w.setAbort(ContainerAbortMaxTime)
			return
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			w.setAbort(ContainerAbortCorrupt)
			return
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		data, overrun := w.readCapped(tr, w.remainBudget())
		if w.abort != ContainerAbortNone || overrun {
			return
		}
		w.considerMember(data, depth)
	}
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	printable := 0
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r != 127) {
			printable++
		}
	}
	// Allow XML/text with modest binary noise.
	return printable*10 >= len([]rune(string(b)))*8
}

// JoinContainerParts concatenates inspected text parts for ExtractTaintedValues.
func JoinContainerParts(parts []string) string {
	return strings.Join(parts, "\n")
}

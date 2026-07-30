package engine

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"testing"
	"time"
)

func TestLooksLikeContainer_ZIP(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("sheet1.xml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("<c>sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef</c>")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if !LooksLikeContainer(raw) {
		t.Fatal("expected ZIP magic detection")
	}
	res := InspectContainer(raw, DefaultContainerLimits())
	if res.Abort != ContainerAbortNone {
		t.Fatalf("unexpected abort %q", res.Abort)
	}
	if len(res.Parts) == 0 {
		t.Fatal("expected interior text parts")
	}
	joined := JoinContainerParts(res.Parts)
	if !bytes.Contains([]byte(joined), []byte("sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef")) {
		t.Fatalf("secret missing from parts: %q", joined)
	}
}

func TestInspectContainer_Gzip(t *testing.T) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	if _, err := gw.Write([]byte("token=" + secret)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	res := InspectContainer(buf.Bytes(), DefaultContainerLimits())
	if res.Abort != ContainerAbortNone {
		t.Fatalf("abort %q", res.Abort)
	}
	if !bytes.Contains([]byte(JoinContainerParts(res.Parts)), []byte(secret)) {
		t.Fatal("gzip interior missing secret")
	}
}

func TestInspectContainer_Zlib(t *testing.T) {
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	secret := "sk-live-51TxJANEd0eR3aLt0k3n9876543210abcdef"
	if _, err := zw.Write([]byte(secret)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	res := InspectContainer(buf.Bytes(), DefaultContainerLimits())
	if res.Abort != ContainerAbortNone {
		t.Fatalf("abort %q", res.Abort)
	}
	if !bytes.Contains([]byte(JoinContainerParts(res.Parts)), []byte(secret)) {
		t.Fatal("zlib interior missing secret")
	}
}

func TestInspectContainer_MaxPartsAbort(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 5; i++ {
		w, err := zw.Create(string(rune('a'+i)) + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("part")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	lim := DefaultContainerLimits()
	lim.MaxParts = 2
	res := InspectContainer(buf.Bytes(), lim)
	if res.Abort != ContainerAbortMaxParts {
		t.Fatalf("abort = %q, want max_parts", res.Abort)
	}
}

func TestInspectContainer_MaxBytesAbort(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("big.txt")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("A"), 1024)
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	lim := DefaultContainerLimits()
	lim.MaxDecompressedBytes = 100
	res := InspectContainer(buf.Bytes(), lim)
	if res.Abort != ContainerAbortMaxBytes {
		t.Fatalf("abort = %q, want max_decompressed_bytes", res.Abort)
	}
}

func TestInspectContainer_Disabled(t *testing.T) {
	lim := DefaultContainerLimits()
	lim.Enabled = false
	res := InspectContainer([]byte("PK\x03\x04"), lim)
	if len(res.Parts) != 0 || res.Abort != ContainerAbortNone {
		t.Fatalf("disabled inspect should no-op, got %+v", res)
	}
}

func TestInspectContainer_TimeBudget(t *testing.T) {
	// Extremely short budget should abort; use a multi-member zip so the
	// walk has something to do after deadline. Soft: may complete before the
	// timer fires on fast machines — hard pin is TestInspectContainer_TimeBudget_HardAbort.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 20; i++ {
		w, err := zw.Create(string(rune('a'+(i%26))) + string(rune('0'+i%10)) + ".txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte("x"), 64)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	lim := DefaultContainerLimits()
	lim.MaxInspect = time.Nanosecond
	_ = InspectContainer(buf.Bytes(), lim)
}

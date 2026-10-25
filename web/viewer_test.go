// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"regexp"
	"testing"
)

// Review #23: evidence fields reach innerHTML, so every item.ref use must go
// through esc().
func TestViewer_ItemRefIsEscaped(t *testing.T) {
	src, err := os.ReadFile("viewer.html")
	if err != nil {
		t.Fatal(err)
	}
	unescaped := regexp.MustCompile(`\+\s*(?:String\()?item\.ref\b`)
	if m := unescaped.Find(src); m != nil {
		t.Fatalf("item.ref concatenated into HTML without esc(): %q", m)
	}
}

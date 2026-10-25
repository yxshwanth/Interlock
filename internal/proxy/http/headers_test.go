// SPDX-License-Identifier: Apache-2.0

package mcphttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidateOrigin_ExactHostname(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://evil.localhost.attacker.com")
	if err := ValidateOrigin(r, []string{"localhost"}); err == nil {
		t.Fatal("expected subdomain bypass to fail")
	}
}

// Review #11 bypass 1: listen ":8080" yields an empty host entry, which a
// substring check matched against every Origin.
func TestValidateOrigin_EmptyAllowedEntryMatchesNothing(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://attacker.example")
	if err := ValidateOrigin(r, []string{""}); err == nil {
		t.Fatal("empty allowed-host entry accepted an arbitrary Origin")
	}
}

func TestValidateOrigin_Allowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://localhost:8080")
	if err := ValidateOrigin(r, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
}

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

func TestValidateOrigin_Allowed(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "http://localhost:8080")
	if err := ValidateOrigin(r, []string{"localhost"}); err != nil {
		t.Fatal(err)
	}
}

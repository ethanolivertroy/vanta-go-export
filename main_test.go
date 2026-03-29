package main

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDownloadRedirect(t *testing.T) {
	t.Run("allows https redirect on same host", func(t *testing.T) {
		err := validateDownloadRedirect(
			&http.Request{URL: mustParseURL(t, "https://downloads.example.com/file")},
			[]*http.Request{{URL: mustParseURL(t, "https://downloads.example.com/start")}},
		)
		if err != nil {
			t.Fatalf("expected redirect to be allowed, got %v", err)
		}
	})

	t.Run("allows https redirect to subdomain", func(t *testing.T) {
		err := validateDownloadRedirect(
			&http.Request{URL: mustParseURL(t, "https://cdn.downloads.example.com/file")},
			[]*http.Request{{URL: mustParseURL(t, "https://downloads.example.com/start")}},
		)
		if err != nil {
			t.Fatalf("expected redirect to subdomain to be allowed, got %v", err)
		}
	})

	t.Run("rejects non-https redirect", func(t *testing.T) {
		err := validateDownloadRedirect(
			&http.Request{URL: mustParseURL(t, "http://downloads.example.com/file")},
			[]*http.Request{{URL: mustParseURL(t, "https://downloads.example.com/start")}},
		)
		if err == nil {
			t.Fatal("expected non-https redirect to be rejected")
		}
	})

	t.Run("rejects redirect to different host", func(t *testing.T) {
		err := validateDownloadRedirect(
			&http.Request{URL: mustParseURL(t, "https://attacker.example.net/file")},
			[]*http.Request{{URL: mustParseURL(t, "https://downloads.example.com/start")}},
		)
		if err == nil {
			t.Fatal("expected redirect to different host to be rejected")
		}
	})
}

func TestEscapeCSVCell(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "safe", input: "Evidence Name", want: "Evidence Name"},
		{name: "formula", input: "=SUM(A1:A2)", want: "'=SUM(A1:A2)"},
		{name: "leading whitespace formula", input: " \t-HYPERLINK(\"http://example.com\")", want: "' \t-HYPERLINK(\"http://example.com\")"},
		{name: "empty", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := escapeCSVCell(tt.input); got != tt.want {
				t.Fatalf("escapeCSVCell(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveSecureOutputPathRejectsSymlinkedParent(t *testing.T) {
	baseDir := t.TempDir()
	outsideDir := t.TempDir()

	linkPath := filepath.Join(baseDir, "control")
	if err := os.Symlink(outsideDir, linkPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := resolveSecureOutputPath(baseDir, filepath.Join(linkPath, "evidence.json"))
	if err == nil {
		t.Fatal("expected symlinked parent directory to be rejected")
	}
}

func TestResolveClientSecret(t *testing.T) {
	t.Run("uses flag secret", func(t *testing.T) {
		secret, err := resolveClientSecret("flag-secret", false, "env-secret", bytes.NewBufferString("stdin-secret"))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if secret != "flag-secret" {
			t.Fatalf("expected flag-secret, got %q", secret)
		}
	})

	t.Run("uses stdin secret", func(t *testing.T) {
		secret, err := resolveClientSecret("", true, "env-secret", bytes.NewBufferString("stdin-secret\n"))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if secret != "stdin-secret" {
			t.Fatalf("expected stdin-secret, got %q", secret)
		}
	})

	t.Run("uses env fallback", func(t *testing.T) {
		secret, err := resolveClientSecret("", false, "env-secret", bytes.NewBufferString(""))
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if secret != "env-secret" {
			t.Fatalf("expected env-secret, got %q", secret)
		}
	})

	t.Run("rejects flag and stdin together", func(t *testing.T) {
		_, err := resolveClientSecret("flag-secret", true, "env-secret", bytes.NewBufferString("stdin-secret"))
		if err == nil {
			t.Fatal("expected conflicting flag and stdin inputs to error")
		}
	})
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", raw, err)
	}
	return parsed
}

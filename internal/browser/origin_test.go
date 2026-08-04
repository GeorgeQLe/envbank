package browser

import "testing"

func TestNormalizeOrigin(t *testing.T) {
	tests := map[string]string{
		"https://Example.COM":      "https://example.com",
		"https://example.com:443":  "https://example.com",
		"https://example.com:8443": "https://example.com:8443",
		"http://localhost:3000":    "http://localhost:3000",
		"http://app.localhost":     "http://app.localhost",
		"http://127.0.0.1":         "http://127.0.0.1",
		"http://[::1]:8080":        "http://[::1]:8080",
	}
	for input, want := range tests {
		got, err := NormalizeOrigin(input)
		if err != nil || got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
}

func TestNormalizeOriginRejectsUnsafeValues(t *testing.T) {
	values := []string{
		"http://example.com", "file:///tmp/a", "chrome://settings", "https://*.example.com",
		"https://user@example.com", "https://example.com/path", "https://example.com/",
		"https://example.com?q=1", "https://example.com#x", "null", "data:text/plain,x",
	}
	for _, value := range values {
		if got, err := NormalizeOrigin(value); err == nil {
			t.Errorf("NormalizeOrigin(%q) unexpectedly succeeded: %q", value, got)
		}
	}
}

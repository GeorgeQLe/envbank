package browser

import (
	"errors"
	"net"
	"net/url"
	"sort"
	"strings"
)

// NormalizeOrigin validates and canonicalizes an origin suitable for an
// encrypted per-secret browser allowlist.
func NormalizeOrigin(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw {
		return "", errors.New("origin must be an exact HTTPS origin or loopback HTTP origin")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return "", errors.New("origin must not contain credentials, a path, query, or fragment")
	}
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || strings.ContainsAny(hostname, "*%") {
		return "", errors.New("origin must contain an exact host without wildcards or zones")
	}
	if !asciiHost(hostname) {
		return "", errors.New("origin host must be ASCII")
	}
	port := u.Port()
	if u.Host != hostname && !strings.HasPrefix(u.Host, "[") && port == "" && !strings.EqualFold(u.Host, hostname) {
		return "", errors.New("origin has an invalid port")
	}
	if scheme == "http" {
		if !isLoopbackHost(hostname) {
			return "", errors.New("HTTP browser origins are limited to loopback hosts")
		}
	} else if scheme != "https" {
		return "", errors.New("origin must use HTTPS, or HTTP on a loopback host")
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return scheme + "://" + host, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func asciiHost(host string) bool {
	for i := 0; i < len(host); i++ {
		c := host[i]
		if c >= 0x80 || !(c == '.' || c == '-' || c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}
	return true
}

func ContainsOrigin(origins []string, origin string) bool {
	for _, allowed := range origins {
		if allowed == origin {
			return true
		}
	}
	return false
}

func AddOrigin(origins []string, origin string) ([]string, bool) {
	if ContainsOrigin(origins, origin) {
		return origins, false
	}
	updated := append(append([]string(nil), origins...), origin)
	sort.Strings(updated)
	return updated, true
}

func RemoveOrigin(origins []string, origin string) ([]string, bool) {
	updated := make([]string, 0, len(origins))
	removed := false
	for _, allowed := range origins {
		if allowed == origin {
			removed = true
			continue
		}
		updated = append(updated, allowed)
	}
	return updated, removed
}

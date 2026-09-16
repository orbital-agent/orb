package tunnel

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// subdomainRe validates subdomain format
	subdomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	// portRe validates port number format
	portRe = regexp.MustCompile(`^\d{1,5}$`)
	// expiresRe validates expires duration format (e.g., 1h, 24h, 7d, 30m)
	expiresRe = regexp.MustCompile(`^(\d+)(m|h|d)$`)
)

// ValidateSubdomain checks if a subdomain string is valid
func ValidateSubdomain(s string) error {
	if !subdomainRe.MatchString(s) {
		return fmt.Errorf("invalid subdomain: use lowercase letters, digits, and hyphens (must start/end with alphanumeric)")
	}
	return nil
}

// ValidatePort checks if a port string is valid
func ValidatePort(p string) error {
	if !portRe.MatchString(p) {
		return fmt.Errorf("invalid port: must be a number between 1-65535")
	}
	return nil
}

// ValidateServiceType checks if a service type is valid
func ValidateServiceType(t string) error {
	for _, valid := range ValidServiceTypes {
		if t == valid {
			return nil
		}
	}
	return fmt.Errorf("invalid service type %q: must be one of %v", t, ValidServiceTypes)
}

// ValidateAccessLevel checks if an access level is valid Accepts "public", "private", or any group name.
func ValidateAccessLevel(level string) error {
	if level == "" {
		return fmt.Errorf("access level cannot be empty")
	}
	// Any non-empty string is valid (public, private, or group name)
	return nil
}

// ValidateExpiresDuration checks if an expires duration string is valid
func ValidateExpiresDuration(expires string) error {
	expires = strings.TrimSpace(expires)
	if !expiresRe.MatchString(expires) {
		return fmt.Errorf("invalid expires format %q: use format like 30m, 1h, 24h, or 7d", expires)
	}
	return nil
}

// ParseExpiresDuration parses an expires string into a time.Duration
func ParseExpiresDuration(expires string) (time.Duration, error) {
	expires = strings.TrimSpace(expires)
	matches := expiresRe.FindStringSubmatch(expires)
	if matches == nil {
		return 0, fmt.Errorf("invalid expires format: %s", expires)
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, err
	}

	unit := matches[2]
	switch unit {
	case "m":
		return time.Duration(value) * time.Minute, nil
	case "h":
		return time.Duration(value) * time.Hour, nil
	case "d":
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown time unit: %s", unit)
	}
}

// CURRENTLY DISABLED FOR BETTER DESIGN PRACTICES EnsurePortListening checks if a service is listening on the given port func EnsurePortListening(port string) error { addr := "127.0.0.1:" + port conn, err := net.DialTimeout("tcp", addr, 800*time.Millisecond) if err != nil { return fmt.Errorf("nothing listening on %s - start your service first", addr) } conn.Close() return nil }.

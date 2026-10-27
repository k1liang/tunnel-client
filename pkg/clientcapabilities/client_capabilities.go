// Package clientcapabilities describes optional protocols implemented by a
// tunnel client, independently of the MCP servers it connects to.
package clientcapabilities

import (
	"errors"
	"slices"
	"strings"
)

const (
	HeaderName = "X-Tunnel-Client-Capabilities"

	// WrongClusterV1 supports learning a replacement polling token from a
	// validated wrong_cluster correction and retrying at the same endpoint.
	WrongClusterV1 = "wrong-cluster-v1"
	TraceContextV1 = "trace-context-v1"

	MaxValueBytes = 4096
	MaxMembers    = 64
	MaxTokenBytes = 128
)

// Set is a case-sensitive set of capability names. Its zero value is empty.
type Set struct {
	names map[string]struct{}
}

// Supports reports exact membership, including names unknown to this package.
func (s Set) Supports(name string) bool {
	_, ok := s.names[name]
	return ok
}

// Parse combines all values of HeaderName, as returned by http.Header.Values.
// Values are comma-separated HTTP tokens with optional space/tab padding.
// Empty list members are ignored and duplicate names are combined. The byte
// limit includes one comma between field values, and the member limit counts
// nonempty members before deduplication. Any invalid or oversized advertisement
// returns an empty set; a valid prefix never enables a capability on its own.
func Parse(values []string) Set {
	if len(values) > MaxValueBytes+1 {
		return Set{}
	}
	total := max(0, len(values)-1)
	for _, value := range values {
		if len(value) > MaxValueBytes-total {
			return Set{}
		}
		total += len(value)
	}
	names := make(map[string]struct{})
	members := 0
	for _, value := range values {
		for member := range strings.SplitSeq(value, ",") {
			name := strings.Trim(member, " \t")
			if name == "" {
				continue
			}
			members++
			if members > MaxMembers || !validName(name) {
				return Set{}
			}
			names[name] = struct{}{}
		}
	}
	return Set{names: names}
}

// Format validates names and emits a sorted, deduplicated comma-separated
// advertisement. Each argument must be one token, without whitespace or commas.
func Format(names ...string) (string, error) {
	if len(names) > MaxMembers {
		return "", errors.New("too many client capabilities")
	}
	for _, name := range names {
		if !validName(name) {
			return "", errors.New("invalid client capability name")
		}
	}
	names = slices.Clone(names)
	slices.Sort(names)
	value := strings.Join(slices.Compact(names), ",")
	if len(value) > MaxValueBytes {
		return "", errors.New("client capabilities exceed size limit")
	}
	return value, nil
}

// Advertised returns only capabilities implemented by this client release.
// Keep registration here, rather than allowing configuration to claim support.
func Advertised() string {
	return WrongClusterV1
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > MaxTokenBytes {
		return false
	}
	for i := range len(name) {
		c := name[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

package api

import (
	"fmt"
	"net/netip"
)

// parseEntry accepts a prefix ("10.0.0.0/8") or a bare address, which
// becomes a host prefix (/32 or /128).
func parseEntry(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("table entry %q is not an address or prefix", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

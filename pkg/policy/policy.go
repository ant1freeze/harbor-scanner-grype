// Package policy decides the Harbor level of a grype finding and explains the decision.
package policy

// ExploitLookup returns the ids of Exploit-DB exploits for a CVE. The returned slice may be
// shared with the index: callers must not modify it.
type ExploitLookup interface {
	Lookup(cve string) []string
}

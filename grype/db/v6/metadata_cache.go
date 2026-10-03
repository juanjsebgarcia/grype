package v6

import (
	"sync"

	"github.com/anchore/grype/grype/vulnerability"
)

// metadataCache memoizes vulnerability.Metadata for the lifetime of a vulnerabilityProvider.
//
// Building metadata takes a KEV, an EPSS and a CWE query for every CVE a record names, and a scan asks
// for the same record many times: once per matching package during search, and again per match when
// the matcher, the severity summary and the presenter look metadata up by reference. The DB behind a
// provider is read-only and does not change while the provider is open, so the metadata for a key
// never changes either and can be shared across the whole scan.
//
// Entries are keyed on everything the result depends on:
//   - byHandle: a vulnerability row (its ID identifies the row and its blob) and the namespace it was
//     found in, which is copied into the result.
//   - byReference: a vulnerability reference that carries no row, by ID and namespace; the row is
//     looked up by name within the provider named by the namespace.
//
// A lookup that returns an error is not stored, so the next call for that key tries again, and neither is
// a reference with no row in the DB, since callers can name any ID and namespace. Metadata built
// while a KEV, EPSS or CWE lookup failed is stored as built, as the per-search cache this replaces did:
// the provider logs those failures and returns the metadata without that data rather than failing.
//
// The cache is safe for concurrent use. It holds at most one entry per (vulnerability, namespace)
// pair the provider finds a row for, so it is bounded by the size of the DB, and in practice by the
// vulnerabilities that match the packages being scanned. Returned metadata is shared between
// callers and must be treated as read-only.
type metadataCache struct {
	byHandle    memo[handleMetadataKey]
	byReference memo[referenceMetadataKey]
}

type handleMetadataKey struct {
	id        ID
	namespace string
}

type referenceMetadataKey struct {
	id        string
	namespace string
}

func newMetadataCache() *metadataCache {
	return &metadataCache{
		byHandle:    memo[handleMetadataKey]{entries: make(map[handleMetadataKey]*vulnerability.Metadata)},
		byReference: memo[referenceMetadataKey]{entries: make(map[referenceMetadataKey]*vulnerability.Metadata)},
	}
}

// forHandle returns the metadata for a vulnerability row found in namespace. A nil cache fetches every time.
func (c *metadataCache) forHandle(key handleMetadataKey, fetch metadataFetcher) (*vulnerability.Metadata, error) {
	if c == nil {
		return fetch()
	}
	return c.byHandle.get(key, fetch)
}

// forReference returns the metadata for a vulnerability reference that carries no row. A nil cache
// fetches every time.
func (c *metadataCache) forReference(key referenceMetadataKey, fetch metadataFetcher) (*vulnerability.Metadata, error) {
	if c == nil {
		return fetch()
	}
	return c.byReference.get(key, fetch)
}

// metadataFetcher builds the metadata for a cache miss.
type metadataFetcher func() (*vulnerability.Metadata, error)

type memo[K comparable] struct {
	mu      sync.RWMutex
	entries map[K]*vulnerability.Metadata
}

// get returns the cached metadata for key, calling fetch on a miss. The fetch runs without holding the
// lock, so concurrent misses for the same key may both query the DB; the first result stored wins and is
// returned to both, so every caller sees the same value for a key.
func (m *memo[K]) get(key K, fetch metadataFetcher) (*vulnerability.Metadata, error) {
	m.mu.RLock()
	metadata, ok := m.entries[key]
	m.mu.RUnlock()
	if ok {
		return metadata, nil
	}

	metadata, err := fetch()
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.entries[key]; ok {
		return existing, nil
	}
	m.entries[key] = metadata
	return metadata, nil
}

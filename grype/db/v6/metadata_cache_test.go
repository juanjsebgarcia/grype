package v6

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/search"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/cpe"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// countingReader counts the DB queries that building metadata makes, and can fail them on demand.
type countingReader struct {
	*store
	vulnerabilityLookups atomic.Int64
	kevLookups           atomic.Int64
	failVulnerability    atomic.Int64 // fail this many GetVulnerabilities calls
	failKEV              atomic.Int64 // fail this many GetKnownExploitedVulnerabilities calls
}

var errInjected = errors.New("injected read failure")

func entries[K comparable](m *memo[K]) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.entries)
}

func (r *countingReader) GetVulnerabilities(vuln *VulnerabilitySpecifier, config *GetVulnerabilityOptions) ([]VulnerabilityHandle, error) {
	r.vulnerabilityLookups.Add(1)
	if r.failVulnerability.Add(-1) >= 0 {
		return nil, errInjected
	}
	return r.store.GetVulnerabilities(vuln, config)
}

func (r *countingReader) GetKnownExploitedVulnerabilities(cve string) ([]KnownExploitedVulnerabilityHandle, error) {
	r.kevLookups.Add(1)
	if r.failKEV.Add(-1) >= 0 {
		return nil, errInjected
	}
	return r.store.GetKnownExploitedVulnerabilities(cve)
}

// metadataTestProvider stores the same CVE under two providers and returns a provider whose reader counts
// queries, with the two stored rows.
func metadataTestProvider(t *testing.T) (*vulnerabilityProvider, *countingReader, *VulnerabilityHandle, *VulnerabilityHandle) {
	t.Helper()
	s := setupTestStore(t)

	nvd := &VulnerabilityHandle{
		Name:       "CVE-2024-3400",
		ProviderID: "nvd",
		Provider:   &Provider{ID: "nvd"},
		BlobValue: &VulnerabilityBlob{
			ID:          "CVE-2024-3400",
			Description: "nvd description",
			References:  []Reference{{URL: "https://nvd.example/CVE-2024-3400"}},
		},
	}
	debian := &VulnerabilityHandle{
		Name:       "CVE-2024-3400",
		ProviderID: "debian",
		Provider:   &Provider{ID: "debian"},
		BlobValue: &VulnerabilityBlob{
			ID:          "CVE-2024-3400",
			Description: "debian description",
			References:  []Reference{{URL: "https://debian.example/CVE-2024-3400"}},
		},
	}
	require.NoError(t, s.AddVulnerabilities(nvd, debian))
	require.NotEqual(t, nvd.ID, debian.ID)

	require.NoError(t, s.AddKnownExploitedVulnerabilities(&KnownExploitedVulnerabilityHandle{
		Cve: "CVE-2024-3400",
		BlobValue: &KnownExploitedVulnerabilityBlob{
			Cve:           "CVE-2024-3400",
			VendorProject: "Palo Alto Networks",
			Product:       "PAN-OS",
		},
	}))

	r := &countingReader{store: s}
	vp := NewVulnerabilityProvider(r).(*vulnerabilityProvider)
	return vp, r, nvd, debian
}

func Test_metadataCache_handles(t *testing.T) {
	vp, r, nvd, debian := metadataTestProvider(t)

	first, err := vp.getCachedMetadata(nvd, "nvd:cpe")
	require.NoError(t, err)
	require.Equal(t, int64(1), r.kevLookups.Load())
	assert.Equal(t, "nvd:cpe", first.Namespace)
	assert.Equal(t, "nvd description", first.Description)
	require.Len(t, first.KnownExploited, 1)

	// hit: no further queries, and the same value is shared
	again, err := vp.getCachedMetadata(nvd, "nvd:cpe")
	require.NoError(t, err)
	assert.Same(t, first, again)
	assert.Equal(t, int64(1), r.kevLookups.Load())

	// hit through the deprecated reference API when the reference carries the row
	byRef, err := vp.VulnerabilityMetadata(vulnerability.Reference{ID: nvd.Name, Namespace: "nvd:cpe", Internal: nvd})
	require.NoError(t, err)
	assert.Same(t, first, byRef)
	assert.Equal(t, int64(1), r.kevLookups.Load())
	assert.Equal(t, int64(0), r.vulnerabilityLookups.Load())

	// miss: the same row in another namespace carries that namespace
	otherNamespace, err := vp.getCachedMetadata(nvd, "nvd:other")
	require.NoError(t, err)
	assert.NotSame(t, first, otherNamespace)
	assert.Equal(t, "nvd:other", otherNamespace.Namespace)
	assert.Equal(t, int64(2), r.kevLookups.Load())

	// miss: another row with the same vulnerability name is not confused with the first
	otherRow, err := vp.getCachedMetadata(debian, "nvd:cpe")
	require.NoError(t, err)
	assert.Equal(t, "debian description", otherRow.Description)
	assert.Equal(t, int64(3), r.kevLookups.Load())

	// no row, no metadata
	none, err := vp.getCachedMetadata(nil, "nvd:cpe")
	require.NoError(t, err)
	assert.Nil(t, none)

	// a handle that was not read from the DB has no row ID to key on, so it is never cached
	unsaved := &VulnerabilityHandle{Name: "CVE-2024-3400", BlobValue: &VulnerabilityBlob{ID: "CVE-2024-3400", Description: "unsaved"}}
	for range 2 {
		got, err := vp.getCachedMetadata(unsaved, "nvd:cpe")
		require.NoError(t, err)
		assert.Equal(t, "unsaved", got.Description)
	}
	assert.Equal(t, int64(5), r.kevLookups.Load())

	assert.Equal(t, 3, entries(&vp.metadata.byHandle))
	assert.Equal(t, 0, entries(&vp.metadata.byReference))
}

func Test_metadataCache_references(t *testing.T) {
	vp, r, _, _ := metadataTestProvider(t)

	ref := vulnerability.Reference{ID: "CVE-2024-3400", Namespace: "nvd:cpe"}
	first, err := vp.VulnerabilityMetadata(ref)
	require.NoError(t, err)
	assert.Equal(t, "nvd description", first.Description)
	assert.Equal(t, "nvd:cpe", first.Namespace)
	require.Equal(t, int64(1), r.vulnerabilityLookups.Load())

	again, err := vp.VulnerabilityMetadata(ref)
	require.NoError(t, err)
	assert.Same(t, first, again)
	assert.Equal(t, int64(1), r.vulnerabilityLookups.Load())

	// the namespace selects the provider the row is looked up in
	debian, err := vp.VulnerabilityMetadata(vulnerability.Reference{ID: "CVE-2024-3400", Namespace: "debian:distro:debian:12"})
	require.NoError(t, err)
	assert.Equal(t, "debian description", debian.Description)
	assert.Equal(t, "debian:distro:debian:12", debian.Namespace)
	assert.Equal(t, int64(2), r.vulnerabilityLookups.Load())

	// a reference with no row in the DB gets placeholder metadata, which is not remembered: callers can name
	// any ID and namespace, so caching misses would let the cache grow without bound
	missing := vulnerability.Reference{ID: "CVE-0000-0000", Namespace: "nvd:cpe"}
	placeholder, err := vp.VulnerabilityMetadata(missing)
	require.NoError(t, err)
	assert.Equal(t, &vulnerability.Metadata{ID: "CVE-0000-0000", DataSource: "nvd", Namespace: "nvd:cpe", Severity: "Unknown"}, placeholder)
	placeholderAgain, err := vp.VulnerabilityMetadata(missing)
	require.NoError(t, err)
	assert.Equal(t, placeholder, placeholderAgain)
	assert.Equal(t, int64(4), r.vulnerabilityLookups.Load())

	// a reference holding a nil row gets placeholder metadata without touching the DB or the cache
	nilRow, err := vp.VulnerabilityMetadata(vulnerability.Reference{ID: "CVE-2024-3400", Namespace: "nvd:cpe", Internal: (*VulnerabilityHandle)(nil)})
	require.NoError(t, err)
	assert.Equal(t, "Unknown", nilRow.Severity)
	assert.Equal(t, int64(4), r.vulnerabilityLookups.Load())

	assert.Equal(t, 2, entries(&vp.metadata.byReference))
}

func Test_metadataCache_failures(t *testing.T) {
	t.Run("row lookup failure", func(t *testing.T) {
		vp, r, _, _ := metadataTestProvider(t)
		ref := vulnerability.Reference{ID: "CVE-2024-3400", Namespace: "nvd:cpe"}

		r.failVulnerability.Store(1)
		_, err := vp.VulnerabilityMetadata(ref)
		require.ErrorIs(t, err, errInjected)
		assert.Equal(t, 0, entries(&vp.metadata.byReference))

		got, err := vp.VulnerabilityMetadata(ref)
		require.NoError(t, err)
		assert.Equal(t, "nvd description", got.Description)
		assert.Equal(t, int64(2), r.vulnerabilityLookups.Load())
	})

	t.Run("decorator lookup failure", func(t *testing.T) {
		vp, r, nvd, _ := metadataTestProvider(t)

		// a failed KEV lookup is logged and the metadata is built without the KEV data, as without the cache;
		// that result is what the provider answers for the rest of its life
		r.failKEV.Store(1)
		degraded, err := vp.getCachedMetadata(nvd, "nvd:cpe")
		require.NoError(t, err)
		assert.Empty(t, degraded.KnownExploited)

		again, err := vp.getCachedMetadata(nvd, "nvd:cpe")
		require.NoError(t, err)
		assert.Same(t, degraded, again)
		assert.Equal(t, int64(1), r.kevLookups.Load())
	})
}

func Test_metadataCache_concurrentUse(t *testing.T) {
	vp, _, nvd, debian := metadataTestProvider(t)

	refs := []vulnerability.Reference{
		{ID: nvd.Name, Namespace: "nvd:cpe", Internal: nvd},
		{ID: debian.Name, Namespace: "debian:distro:debian:12", Internal: debian},
		{ID: "CVE-2024-3400", Namespace: "nvd:cpe"},
		{ID: "CVE-0000-0000", Namespace: "nvd:cpe"},
	}

	const workers = 16
	results := make([][]*vulnerability.Metadata, workers)
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				for _, ref := range refs {
					m, err := vp.VulnerabilityMetadata(ref)
					assert.NoError(t, err)
					results[w] = append(results[w], m)
				}
			}
		}()
	}
	wg.Wait()

	// every caller sees the one stored value for a key, and an equal placeholder for the miss, which is not stored
	for w := range workers {
		for i, m := range results[w] {
			want := results[0][i%len(refs)]
			if refs[i%len(refs)].ID == "CVE-0000-0000" {
				assert.Equal(t, want, m)
				continue
			}
			assert.Same(t, want, m)
		}
	}
	assert.Equal(t, 2, entries(&vp.metadata.byHandle))
	assert.Equal(t, 1, entries(&vp.metadata.byReference))
}

// Test_metadataCache_matchesUncached runs the same searches and reference lookups through a provider that
// caches and one that does not (nil cache), and requires the same results from both, before and after the
// cache is warm.
func Test_metadataCache_matchesUncached(t *testing.T) {
	cached := testVulnerabilityProvider(t).(*vulnerabilityProvider)
	uncached := &vulnerabilityProvider{reader: cached.reader, archAliases: cached.archAliases}
	require.NotNil(t, cached.metadata)

	searches := [][]vulnerability.Criteria{
		{search.ByDistro(*distro.New(distro.Debian, "8", "")), search.ByPackageName("neutron")},
		{search.ByDistro(*distro.New(distro.Debian, "8", "")), search.ByID("CVE-2014-fake-1")},
		{search.ByCPE(cpe.Must("cpe:2.3:*:activerecord:activerecord:*:*:*:*:*:ruby:*:*", ""))},
		{search.ByEcosystem(syftPkg.Dotnet, syftPkg.DotnetPkg), search.ByPackageName("Newtonsoft.Json")},
		{search.ByPackageName("test-unaffected-package"), search.ForUnaffected()},
	}

	var refs []vulnerability.Reference
	for pass := range 2 {
		for i, criteria := range searches {
			want, err := uncached.FindVulnerabilities(criteria...)
			require.NoError(t, err)
			got, err := cached.FindVulnerabilities(criteria...)
			require.NoError(t, err)
			require.NotEmpty(t, want, "search %d returned nothing", i)
			if d := cmp.Diff(want, got, cmpOpts()...); d != "" {
				t.Errorf("pass %d: cached search differs from uncached (-want +got):\n%s", pass, d)
			}
			for _, v := range got {
				refs = append(refs, v.Reference, vulnerability.Reference{ID: v.ID, Namespace: v.Namespace})
				refs = append(refs, v.RelatedVulnerabilities...)
			}
		}
		for _, ref := range refs {
			want, err := uncached.VulnerabilityMetadata(ref)
			require.NoError(t, err)
			got, err := cached.VulnerabilityMetadata(ref)
			require.NoError(t, err)
			if d := cmp.Diff(want, got, cmpOpts()...); d != "" {
				t.Errorf("pass %d: cached metadata for %s/%s differs from uncached (-want +got):\n%s", pass, ref.ID, ref.Namespace, d)
			}
		}
	}
	assert.NotZero(t, entries(&cached.metadata.byHandle))
	assert.NotZero(t, entries(&cached.metadata.byReference))
}

func Benchmark_VulnerabilityMetadata(b *testing.B) {
	s := setupTestStore(b)
	vuln := &VulnerabilityHandle{
		Name:       "CVE-2024-3400",
		ProviderID: "nvd",
		Provider:   &Provider{ID: "nvd"},
		BlobValue:  &VulnerabilityBlob{ID: "CVE-2024-3400", Aliases: []string{"GHSA-xxxx-xxxx-xxxx"}},
	}
	require.NoError(b, s.AddVulnerabilities(vuln))
	ref := vulnerability.Reference{ID: vuln.Name, Namespace: "nvd:cpe", Internal: vuln}

	cached := NewVulnerabilityProvider(s).(*vulnerabilityProvider)
	uncached := &vulnerabilityProvider{reader: s}
	for name, vp := range map[string]*vulnerabilityProvider{"cached": cached, "uncached": uncached} {
		b.Run(name, func(b *testing.B) {
			for b.Loop() {
				if _, err := vp.VulnerabilityMetadata(ref); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

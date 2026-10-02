package models

import (
	"fmt"
	"testing"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

// BenchmarkNewDocument measures building the document for a large package collection where every package
// has one match and one ignored match, so the cost of resolving each match to its package dominates.
func BenchmarkNewDocument(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("packages=%d", size), func(b *testing.B) {
			packages := make([]pkg.Package, size)
			matches := match.NewMatches()
			ignoredMatches := make([]match.IgnoredMatch, 0, size)
			for i := range packages {
				packages[i] = pkg.Package{
					ID:      pkg.ID(fmt.Sprintf("package-%d-id", i)),
					Name:    fmt.Sprintf("package-%d", i),
					Version: "1.0.0",
					Type:    syftPkg.DebPkg,
				}
				matches.Add(match.Match{
					Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-1999-0001"}},
					Package:       packages[i],
					Details:       match.Details{{Type: match.ExactDirectMatch}},
				})
				ignoredMatches = append(ignoredMatches, match.IgnoredMatch{
					Match: match.Match{
						Vulnerability: vulnerability.Vulnerability{Reference: vulnerability.Reference{ID: "CVE-1999-0002"}},
						Package:       packages[i],
						Details:       match.Details{{Type: match.ExactDirectMatch}},
					},
				})
			}
			metadata := NewMetadataMock()

			b.ReportAllocs()
			for b.Loop() {
				if _, err := NewDocument(clio.Identification{}, packages, pkg.Context{}, matches, ignoredMatches, metadata, nil, nil, SortByPackage, false, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

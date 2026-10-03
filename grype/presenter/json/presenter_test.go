package json

import (
	"bytes"
	"encoding/json"
	"flag"
	"regexp"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/internal"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/internal/testutils"
	"github.com/anchore/syft/syft/source"
)

var update = flag.Bool("update", false, "update the *.golden files for json presenters")
var timestampRegexp = regexp.MustCompile(`"timestamp":\s*"[^"]+"`)

func TestJsonImgsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.ImageSource)

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestJsonDirsPresenter(t *testing.T) {
	var buffer bytes.Buffer

	pb := internal.GeneratePresenterConfig(t, internal.DirectorySource)

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	if d := cmp.Diff(string(expected), string(actual)); d != "" {
		t.Fatalf("diff: %s", d)
	}

	// TODO: add me back in when there is a JSON schema
	// validateAgainstDbSchema(t, string(actual))
}

func TestEmptyJsonPresenter(t *testing.T) {
	// expected to have an empty JSON array back
	var buffer bytes.Buffer

	ctx := pkg.Context{
		Source: &source.Description{},
		Distro: &distro.Distro{
			Type:    "centos",
			IDLike:  []string{"rhel"},
			Version: "8.0",
		},
	}

	doc, err := models.NewDocument(clio.Identification{Name: "grype", Version: "[not provided]"}, nil, ctx, match.NewMatches(), nil, models.NewMetadataMock(), nil, nil, models.SortByPackage, true, nil)
	require.NoError(t, err)

	pb := models.PresenterConfig{
		ID: clio.Identification{
			Name:    "grype",
			Version: "[not provided]",
		},
		Document: doc,
	}

	pres := NewPresenter(pb)

	// run presenter
	if err := pres.Present(&buffer); err != nil {
		t.Fatal(err)
	}
	actual := buffer.Bytes()
	actual = redact(actual)

	if *update {
		testutils.UpdateGoldenFileContents(t, actual)
	}

	var expected = testutils.GetGoldenFileContents(t)

	assert.JSONEq(t, string(expected), string(actual))

}

func TestJsonPresenterWithIgnoredMatchesOmitted(t *testing.T) {
	present := func(doc models.Document) map[string]json.RawMessage {
		t.Helper()
		var buffer bytes.Buffer
		pres := NewPresenter(models.PresenterConfig{
			ID:       clio.Identification{Name: "grype", Version: "[not provided]"},
			Document: doc,
			Pretty:   true,
		})
		require.NoError(t, pres.Present(&buffer))

		var sections map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(redact(buffer.Bytes()), &sections))
		return sections
	}

	full := present(internal.GenerateAnalysisWithIgnoredMatches(t, internal.ImageSource))
	omitted := present(internal.GenerateAnalysisWithIgnoredMatchesOmitted(t, internal.ImageSource))

	// precondition: the default document reports ignored matches
	require.Contains(t, full, "ignoredMatches")
	var ignored []json.RawMessage
	require.NoError(t, json.Unmarshal(full["ignoredMatches"], &ignored))
	require.NotEmpty(t, ignored)

	// the section is absent rather than an empty list or null
	assert.NotContains(t, omitted, "ignoredMatches")

	// every other section is byte-identical
	delete(full, "ignoredMatches")
	require.Equal(t, len(full), len(omitted))
	for key, want := range full {
		assert.Equal(t, string(want), string(omitted[key]), "section %q differs", key)
	}
	for _, key := range []string{"matches", "source", "distro", "descriptor"} {
		assert.Contains(t, omitted, key)
	}
}

func redact(content []byte) []byte {
	return timestampRegexp.ReplaceAll(content, []byte(`"timestamp":""`))
}

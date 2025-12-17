package repositories

import (
	"os"
	"path/filepath"
	"testing"

	"patchmon-agent/pkg/models"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestPacmanManager() *PacmanManager {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	return NewPacmanManager(logger)
}

func TestPacman_parsePacmanConf_withServersAndIncludes(t *testing.T) {
	m := newTestPacmanManager()
	dir := t.TempDir()

	// Create included mirrorlist file
	mirrorPath := filepath.Join(dir, "mirrorlist")
	mirrorContent := `
# Arch mirrors
Server = https://mirror1.example.org/archlinux/$repo/os/$arch
; comment
  Server= http://insecure.example.net/archlinux/$repo/os/$arch
`
	require.NoError(t, os.WriteFile(mirrorPath, []byte(mirrorContent), 0o644))

	// Create main pacman.conf
	confPath := filepath.Join(dir, "pacman.conf")
	confContent := `
[options]
Color

[core]
Include = ` + mirrorPath + `

[custom]
Server = https://repo.example.com/$repo/os/$arch

[insecure]
Server = http://repo.insecure.local/$repo/os/$arch

# [commented.out]
# Include = ` + mirrorPath + `
# Server = https://this.should.not.show.up

[commented.include]
Server = https://repo.example.com/$repo/os/$arch
# Include = ` + mirrorPath + `
`
	require.NoError(t, os.WriteFile(confPath, []byte(confContent), 0o644))

	repos, err := m.parsePacmanConf(confPath)
	require.NoError(t, err)

	// Expect 1 from [custom], 1 from [insecure], and 2 from [core] includes = 4
	// However, only URLs with http/https/file are accepted; all entries qualify.
	assert.Len(t, repos, 5)

	// Validate a few properties
	// Find custom https
	var foundCustom, foundCoreHTTPS, foundCoreHTTP, foundInsecure bool
	for _, r := range repos {
		switch r.Name {
		case "custom":
			if r.URL == "https://repo.example.com/$repo/os/$arch" {
				foundCustom = true
				assert.True(t, r.IsSecure)
			}
		case "core":
			if r.URL == "https://mirror1.example.org/archlinux/$repo/os/$arch" {
				foundCoreHTTPS = true
				assert.True(t, r.IsSecure)
			}
			if r.URL == "http://insecure.example.net/archlinux/$repo/os/$arch" {
				foundCoreHTTP = true
				assert.False(t, r.IsSecure)
			}
		case "insecure":
			if r.URL == "http://repo.insecure.local/$repo/os/$arch" {
				foundInsecure = true
				assert.False(t, r.IsSecure)
			}
		case "commented.out":
			assert.Fail(t, "Commented sections should not be parsed")
		case "commented.include":
			// Fail if we ended up actually including this
			if r.URL == "https://mirror1.example.org/archlinux/$repo/os/$arch" {
				assert.Fail(t, "We seem to have traversed a commented out include.")
			}
		}
		// Common expectations
		assert.Equal(t, r.Name, r.Distribution)
		assert.Equal(t, "", r.Components)
		assert.True(t, r.IsEnabled)
	}

	assert.True(t, foundCustom)
	assert.True(t, foundCoreHTTPS)
	assert.True(t, foundCoreHTTP)
	assert.True(t, foundInsecure)
}

func TestPacman_expandIncludeGlobs(t *testing.T) {
	m := newTestPacmanManager()
	dir := t.TempDir()

	// Create two mirrorlist files matching a glob
	ml1 := filepath.Join(dir, "m1.list")
	ml2 := filepath.Join(dir, "m2.list")
	require.NoError(t, os.WriteFile(ml1, []byte("Server = https://a.example/arch/$repo/os/$arch\n"), 0o644))
	require.NoError(t, os.WriteFile(ml2, []byte("Server = https://b.example/arch/$repo/os/$arch\n"), 0o644))

	// Build a pacman.conf that includes the glob
	conf := filepath.Join(dir, "pacman.conf")
	content := "[core]\nInclude = " + filepath.Join(dir, "*.list") + "\n"
	require.NoError(t, os.WriteFile(conf, []byte(content), 0o644))

	repos, err := m.parsePacmanConf(conf)
	require.NoError(t, err)
	assert.Len(t, repos, 2)

	urls := map[string]bool{}
	for _, r := range repos {
		urls[r.URL] = true
		assert.Equal(t, "core", r.Name)
	}
	assert.True(t, urls["https://a.example/arch/$repo/os/$arch"])
	assert.True(t, urls["https://b.example/arch/$repo/os/$arch"])
}

func TestPacman_parseMirrorList_ignoresCommentsAndMalformed(t *testing.T) {
	m := newTestPacmanManager()
	dir := t.TempDir()

	file := filepath.Join(dir, "mirrorlist")
	data := `
# comment
; another
NotAKey = something
Server = https://valid.example/arch/$repo/os/$arch
Server https://missing.equals/arch/$repo/os/$arch
Server = ftp://unsupported.example/path
Server = file:///should/be/ignored
`
	require.NoError(t, os.WriteFile(file, []byte(data), 0o644))

	repos := m.parseMirrorList(file, "extra")
	// Two valid: https and ftp; file:// must be ignored to match DNF behavior; malformed is ignored
	require.Len(t, repos, 2)

	// Build a quick lookup for assertions
	byURL := map[string]models.Repository{}
	for _, r := range repos {
		byURL[r.URL] = r
		assert.Equal(t, "extra", r.Name)
		assert.Equal(t, "extra", r.Distribution)
	}

	httpsRepo, ok := byURL["https://valid.example/arch/$repo/os/$arch"]
	require.True(t, ok)
	assert.True(t, httpsRepo.IsSecure)

	ftpRepo, ok := byURL["ftp://unsupported.example/path"]
	require.True(t, ok)
	assert.False(t, ftpRepo.IsSecure)

	// Ensure file:// is excluded
	_, hasFile := byURL["file:///should/be/ignored"]
	assert.False(t, hasFile)
}

func TestPacman_isValidRepoURL(t *testing.T) {
	m := &PacmanManager{}

	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{"http URL", "http://example.com", true},
		{"https URL", "https://example.com", true},
		{"ftp URL", "ftp://example.com", true},
		{"file URL", "file:///local/path", false},
		{"empty URL", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := m.isValidRepoURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

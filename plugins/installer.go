package plugins

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/routewarden/tcp-warden/plugins/sdk"
)

// InstallOptions configures plugin installation.
type InstallOptions struct {
	PluginsDir string // root directory for plugins (default: "./plugins")
	ProjectDir string // root directory of tcp-warden project (default: ".")
	CacheDir   string // root cache directory (default: GetPluginsCacheDir())
	NoBuild    bool   // skip rebuilding tcp-warden binary
	Force      bool   // overwrite existing plugin / bypass cache
}

// InstallResult details the outcome of an installation.
type InstallResult struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Protocols   []string     `json:"protocols"`
	Source      string       `json:"source"`
	TestPassed  bool         `json:"test_passed"`
	TestOutput  string       `json:"test_output,omitempty"`
	Status      PluginStatus `json:"status"`
	InstalledAt time.Time    `json:"installed_at"`
	Rebuilt     bool         `json:"rebuilt"`
}

// InstalledPluginEntry records metadata for installed plugins in plugins.json.
type InstalledPluginEntry struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Protocols   []string     `json:"protocols"`
	Source      string       `json:"source"`
	Status      PluginStatus `json:"status"`
	TestError   string       `json:"test_error,omitempty"`
	InstalledAt time.Time    `json:"installed_at"`
}

type installedRegistry struct {
	Installed []InstalledPluginEntry `json:"installed"`
	Enabled   []string               `json:"enabled,omitempty"`
	Disabled  []string               `json:"disabled,omitempty"`
}

// InstallPlugin installs a plugin from a GitHub URL or local repository path.
func InstallPlugin(source string, opts InstallOptions) (*InstallResult, error) {
	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	opts.PluginsDir = ResolvePluginsDir(opts.PluginsDir, opts.ProjectDir)
	if !filepath.IsAbs(opts.PluginsDir) && !strings.HasPrefix(opts.PluginsDir, opts.ProjectDir) {
		opts.PluginsDir = filepath.Join(opts.ProjectDir, opts.PluginsDir)
	}

	source = strings.TrimSpace(source)
	if source == "" {
		return nil, errors.New("plugin source cannot be empty")
	}

	// 1. Fetch or prepare plugin source directory
	stagingDir, isTemp, err := stagePluginSource(source)
	if err != nil {
		return nil, fmt.Errorf("staging plugin from %s: %w", source, err)
	}
	if isTemp {
		defer os.RemoveAll(stagingDir)
	}

	// 2. Read and validate plugin.yaml manifest
	manifestPath := filepath.Join(stagingDir, "plugin.yaml")
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		// Check plugin.yml
		manifestPath = filepath.Join(stagingDir, "plugin.yml")
		if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("no plugin.yaml found in %s", source)
		}
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", manifestPath, err)
	}

	var manifest sdk.Manifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing plugin manifest: %w", err)
	}

	manifest.Name = strings.ToLower(strings.TrimSpace(manifest.Name))
	if manifest.Name == "" {
		return nil, errors.New("plugin manifest missing required 'name' field")
	}
	if len(manifest.Protocols) == 0 {
		return nil, errors.New("plugin manifest missing required 'protocols' field")
	}

	targetDir := filepath.Join(opts.PluginsDir, manifest.Name)
	stagingAbs, _ := filepath.Abs(stagingDir)
	targetAbs, _ := filepath.Abs(targetDir)

	// Copy to target directory if not already there
	if stagingAbs != targetAbs {
		if _, err := os.Stat(targetDir); err == nil {
			if opts.Force {
				_ = os.RemoveAll(targetDir)
				if err := copyDir(stagingDir, targetDir); err != nil {
					return nil, fmt.Errorf("copying plugin to %s: %w", targetDir, err)
				}
			} else {
				return nil, fmt.Errorf("plugin %q already installed at %s; use --force to overwrite", manifest.Name, targetDir)
			}
		} else {
			if err := copyDir(stagingDir, targetDir); err != nil {
				return nil, fmt.Errorf("copying plugin to %s: %w", targetDir, err)
			}
		}
	}

	// 3. Pre-flight Automated Test Execution: run 'go test' before loading plugin
	testCmd := exec.Command("go", "test", "-v", "./...")
	testCmd.Dir = targetDir
	var testOut bytes.Buffer
	testCmd.Stdout = &testOut
	testCmd.Stderr = &testOut

	testErr := testCmd.Run()
	testPassed := testErr == nil
	pluginStatus := StatusActive
	testErrStr := ""

	if testErr != nil {
		pluginStatus = StatusDisabled
		testErrStr = fmt.Sprintf("tests failed: %v", testErr)
	}

	// 4. Update plugins/all/all.go to include new plugin import
	allGoPath := filepath.Join(opts.PluginsDir, "all", "all.go")
	if err := registerInAllGo(allGoPath, manifest.Name); err != nil {
		return nil, fmt.Errorf("registering plugin in all.go: %w", err)
	}

	// 5. Update plugins.json registry
	installedEntry := InstalledPluginEntry{
		Name:        manifest.Name,
		Version:     manifest.Version,
		Description: manifest.Description,
		Protocols:   manifest.Protocols,
		Source:      source,
		Status:      pluginStatus,
		TestError:   testErrStr,
		InstalledAt: time.Now().UTC(),
	}
	_ = saveInstalledEntry(opts.ProjectDir, installedEntry)
	if testPassed {
		_ = SavePluginEnablement(opts.ProjectDir, manifest.Name, true)
	} else {
		_ = SavePluginEnablement(opts.ProjectDir, manifest.Name, false)
	}

	// 6. Rebuild tcp-warden binary if enabled
	rebuilt := false
	if !opts.NoBuild {
		buildCmd := exec.Command("go", "build", "-o", "tcp-warden", ".")
		buildCmd.Dir = opts.ProjectDir
		if buildOut, bErr := buildCmd.CombinedOutput(); bErr != nil {
			return nil, fmt.Errorf("rebuilding tcp-warden with new plugin: %v (output: %s)", bErr, string(buildOut))
		}
		rebuilt = true
		updateInstalledExecutable(filepath.Join(opts.ProjectDir, "tcp-warden"))
	}

	res := &InstallResult{
		Name:        manifest.Name,
		Version:     manifest.Version,
		Protocols:   manifest.Protocols,
		Source:      source,
		TestPassed:  testPassed,
		TestOutput:  testOut.String(),
		Status:      pluginStatus,
		InstalledAt: installedEntry.InstalledAt,
		Rebuilt:     rebuilt,
	}

	return res, nil
}

// ResolveProjectDir returns the root directory of the tcp-warden project containing go.mod and plugins/.
// Priority:
// 1. Explicit customDir if non-empty and not "."
// 2. ROUTEWARDEN_SRC_DIR or ROUTEWARDEN_PROJECT_DIR environment variable
// 3. Current working directory if go.mod or plugins/all/all.go exists
// 4. Standard container source locations (/usr/src/tcp-warden, /src)
// 5. Fallback to "."
func ResolveProjectDir(customDir string) string {
	if customDir != "" && customDir != "." {
		return customDir
	}
	if env := os.Getenv("ROUTEWARDEN_SRC_DIR"); env != "" {
		if fi, err := os.Stat(env); err == nil && fi.IsDir() {
			return env
		}
	}
	if env := os.Getenv("ROUTEWARDEN_PROJECT_DIR"); env != "" {
		if fi, err := os.Stat(env); err == nil && fi.IsDir() {
			return env
		}
	}
	if _, err := os.Stat(filepath.Join(".", "plugins", "all", "all.go")); err == nil {
		return "."
	}
	if _, err := os.Stat("go.mod"); err == nil {
		return "."
	}
	candidates := []string{"/usr/src/tcp-warden", "/src"}
	for _, cand := range candidates {
		if _, err := os.Stat(filepath.Join(cand, "plugins", "all", "all.go")); err == nil {
			return cand
		}
		if _, err := os.Stat(filepath.Join(cand, "go.mod")); err == nil {
			return cand
		}
	}
	if customDir != "" {
		return customDir
	}
	return "."
}

// ResolvePluginsDir returns the directory containing the modular plugins.
func ResolvePluginsDir(customPluginsDir string, projectDir string) string {
	if customPluginsDir != "" && customPluginsDir != "plugins" {
		return customPluginsDir
	}
	if _, err := os.Stat(filepath.Join(".", "plugins", "all", "all.go")); err == nil {
		return "plugins"
	}
	if projectDir != "" && projectDir != "." {
		return filepath.Join(projectDir, "plugins")
	}
	return "plugins"
}

// updateInstalledExecutable updates the currently running binary (such as /usr/local/bin/tcp-warden)
// with the newly built binary if running from a different path.
func updateInstalledExecutable(newBinaryPath string) {
	execPath, err := os.Executable()
	if err != nil {
		return
	}
	if resolvedExec, err := filepath.EvalSymlinks(execPath); err == nil {
		execPath = resolvedExec
	}

	absExec, err := filepath.Abs(execPath)
	if err != nil {
		return
	}
	absNew, err := filepath.Abs(newBinaryPath)
	if err != nil {
		return
	}

	if absExec == absNew {
		return
	}

	// Copy new binary to temporary file alongside target executable, then atomic rename
	tmpTarget := absExec + ".tmp"
	if err := copyFile(absNew, tmpTarget); err != nil {
		return
	}
	_ = os.Chmod(tmpTarget, 0755)
	if err := os.Rename(tmpTarget, absExec); err != nil {
		_ = os.Remove(tmpTarget)
	}
}

// GetPluginsCacheDir returns the directory used to cache downloaded plugins.
// Priority:
// 1. Environment variable ROUTEWARDEN_PLUGINS_CACHE
// 2. /var/lib/routewarden/plugins (used in Docker volumes)
// 3. ./.plugins_cache (local fallback)
func GetPluginsCacheDir() string {
	if env := os.Getenv("ROUTEWARDEN_PLUGINS_CACHE"); env != "" {
		return env
	}

	dockerDir := "/var/lib/routewarden/plugins"
	if fi, err := os.Stat(dockerDir); err == nil && fi.IsDir() {
		return dockerDir
	}

	// If root / in container, try to ensure /var/lib/routewarden/plugins exists
	if err := os.MkdirAll(dockerDir, 0755); err == nil {
		return dockerDir
	}

	return ".plugins_cache"
}

// SyncPluginFromSource installs or updates a plugin from source (using cache if already pulled, or pulling fresh).
func SyncPluginFromSource(name string, source string, opts InstallOptions) (*InstallResult, error) {
	if opts.CacheDir == "" {
		opts.CacheDir = GetPluginsCacheDir()
	}
	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	opts.PluginsDir = ResolvePluginsDir(opts.PluginsDir, opts.ProjectDir)

	name = strings.ToLower(strings.TrimSpace(name))
	source = strings.TrimSpace(source)
	if source == "" {
		return nil, errors.New("plugin source cannot be empty")
	}

	// 1. If name is already provided, check if cached manifest exists
	if name != "" {
		cachedPluginDir := filepath.Join(opts.CacheDir, name)
		cachedManifest := filepath.Join(cachedPluginDir, "plugin.yaml")
		if _, err := os.Stat(cachedManifest); os.IsNotExist(err) {
			cachedManifest = filepath.Join(cachedPluginDir, "plugin.yml")
		}

		if _, err := os.Stat(cachedManifest); err == nil && !opts.Force {
			fmt.Printf("✓ [PLUGIN CACHE] Using cached version for %q from %s\n", name, cachedPluginDir)
			cacheOpts := opts
			cacheOpts.Force = true // cache is the source of truth; always sync from it
			return InstallPlugin(cachedPluginDir, cacheOpts)
		}
	}

	// 2. Otherwise stage plugin source (fetches Git or validates local dir)
	fmt.Printf("📥 [PLUGIN] Fetching plugin from %s...\n", source)
	stagedDir, isTemp, err := stagePluginSource(source)
	if err != nil {
		return nil, fmt.Errorf("fetching plugin from %s: %w", source, err)
	}
	if isTemp {
		defer os.RemoveAll(stagedDir)
	}

	// Read manifest to determine actual plugin name
	mPath := filepath.Join(stagedDir, "plugin.yaml")
	if _, err := os.Stat(mPath); os.IsNotExist(err) {
		mPath = filepath.Join(stagedDir, "plugin.yml")
	}
	mData, err := os.ReadFile(mPath)
	if err != nil {
		return nil, fmt.Errorf("reading manifest from staged source %s: %w", source, err)
	}
	var m sdk.Manifest
	if err := yaml.Unmarshal(mData, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest from staged source %s: %w", source, err)
	}

	actualName := strings.ToLower(strings.TrimSpace(m.Name))
	if actualName == "" {
		return nil, fmt.Errorf("plugin manifest in %s missing required 'name' field", source)
	}
	name = actualName

	// 3. Cache the staged plugin in opts.CacheDir/<name>
	cachedPluginDir := filepath.Join(opts.CacheDir, name)
	if err := os.MkdirAll(opts.CacheDir, 0755); err != nil {
		return nil, fmt.Errorf("creating plugin cache directory %s: %w", opts.CacheDir, err)
	}

	_ = os.RemoveAll(cachedPluginDir)
	if err := copyDir(stagedDir, cachedPluginDir); err != nil {
		return nil, fmt.Errorf("caching plugin %q to %s: %w", name, cachedPluginDir, err)
	}

	fmt.Printf("✓ [PLUGIN CACHE] Successfully cached fresh plugin %q at %s\n", name, cachedPluginDir)
	cacheOpts := opts
	cacheOpts.Force = true // freshly pulled source; always overwrite existing install
	return InstallPlugin(cachedPluginDir, cacheOpts)
}

// ParseGitSource splits a GitHub URL into a cloneable repository URL and an internal subpath.
func ParseGitSource(source string) (repoURL string, subPath string) {
	clean := strings.TrimPrefix(source, "https://")
	clean = strings.TrimPrefix(clean, "http://")
	clean = strings.TrimPrefix(clean, "git@github.com:")
	clean = strings.TrimPrefix(clean, "github.com/")

	parts := strings.Split(clean, "/")
	if len(parts) >= 2 {
		owner := parts[0]
		repo := strings.TrimSuffix(parts[1], ".git")
		repoURL = fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)

		if len(parts) >= 4 && (parts[2] == "tree" || parts[2] == "blob") {
			subPath = strings.Join(parts[4:], "/")
		} else if len(parts) > 2 {
			subPath = strings.Join(parts[2:], "/")
		}
		return repoURL, subPath
	}

	return source, ""
}

// stagePluginSource determines if source is a local directory or Git URL and returns directory path.
func stagePluginSource(source string) (string, bool, error) {
	// 1. Check if local directory directly
	info, err := os.Stat(source)
	if err == nil && info.IsDir() {
		return source, false, nil
	}

	// 2. Check if local sibling ../plugins/<source> or ../plugins exists
	localSibling := filepath.Join("..", "plugins", source)
	if sInfo, err := os.Stat(localSibling); err == nil && sInfo.IsDir() {
		return localSibling, false, nil
	}
	localInPlugins := filepath.Join("..", "plugins")
	if sInfo, err := os.Stat(filepath.Join(localInPlugins, source)); err == nil && sInfo.IsDir() {
		return filepath.Join(localInPlugins, source), false, nil
	}

	// 3. If bare plugin name without slashes, fallback to official routewarden/plugins repository
	if !strings.Contains(source, "/") && !strings.Contains(source, "\\") {
		source = "https://github.com/routewarden/plugins/" + source
	}

	// 4. Check if Git / GitHub URL
	isGit := strings.HasPrefix(source, "http://") ||
		strings.HasPrefix(source, "https://") ||
		strings.HasPrefix(source, "git@") ||
		strings.HasPrefix(source, "github.com/")

	if isGit {
		repoURL, subPath := ParseGitSource(source)
		if strings.HasPrefix(repoURL, "github.com/") {
			repoURL = "https://" + repoURL
		}

		cloneDir, err := os.MkdirTemp("", "tcp-warden-clone-*")
		if err != nil {
			return "", false, err
		}
		defer os.RemoveAll(cloneDir)

		cloneCmd := exec.Command("git", "clone", "--depth", "1", repoURL, cloneDir)
		if out, err := cloneCmd.CombinedOutput(); err != nil {
			return "", false, fmt.Errorf("git clone failed for %s: %v (%s)", repoURL, err, string(out))
		}

		sourceDir := cloneDir
		if subPath != "" {
			sourceDir = filepath.Join(cloneDir, subPath)
			if _, err := os.Stat(sourceDir); os.IsNotExist(err) {
				return "", false, fmt.Errorf("plugin subpath %q not found in repository %s", subPath, repoURL)
			}
		}

		finalTmpDir, err := os.MkdirTemp("", "tcp-warden-plugin-*")
		if err != nil {
			return "", false, err
		}

		if err := copyDir(sourceDir, finalTmpDir); err != nil {
			os.RemoveAll(finalTmpDir)
			return "", false, fmt.Errorf("staging cloned plugin files: %w", err)
		}

		return finalTmpDir, true, nil
	}

	return "", false, fmt.Errorf("source %q is neither a valid local directory nor a recognized Git URL", source)
}

// registerInAllGo adds import statement to plugins/all/all.go if not already present.
func registerInAllGo(allGoPath string, pluginName string) error {
	content, err := os.ReadFile(allGoPath)
	if err != nil {
		if os.IsNotExist(err) {
			if mErr := os.MkdirAll(filepath.Dir(allGoPath), 0755); mErr != nil {
				return fmt.Errorf("creating directory for %s: %w", allGoPath, mErr)
			}
			content = []byte("package all\n\nimport (\n)\n")
		} else {
			return err
		}
	}

	importPath := fmt.Sprintf(`_ "github.com/routewarden/tcp-warden/plugins/%s"`, pluginName)
	if strings.Contains(string(content), importPath) {
		return nil
	}

	// Insert before closing parenthesis of import block
	s := string(content)
	lastParen := strings.LastIndex(s, ")")
	if lastParen == -1 {
		return fmt.Errorf("malformed %s, could not find closing parenthesis", allGoPath)
	}

	newContent := s[:lastParen] + "\t" + importPath + "\n" + s[lastParen:]
	return os.WriteFile(allGoPath, []byte(newContent), 0644)
}

func unregisterFromAllGo(allGoPath string, pluginName string) error {
	content, err := os.ReadFile(allGoPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string
	needle := fmt.Sprintf(`"github.com/routewarden/tcp-warden/plugins/%s"`, pluginName)

	for _, line := range lines {
		if strings.Contains(line, needle) {
			continue
		}
		newLines = append(newLines, line)
	}

	return os.WriteFile(allGoPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// UninstallPlugin removes an installed plugin.
func UninstallPlugin(name string, opts InstallOptions) error {
	opts.ProjectDir = ResolveProjectDir(opts.ProjectDir)
	opts.PluginsDir = ResolvePluginsDir(opts.PluginsDir, opts.ProjectDir)
	if !filepath.IsAbs(opts.PluginsDir) && !strings.HasPrefix(opts.PluginsDir, opts.ProjectDir) {
		opts.PluginsDir = filepath.Join(opts.ProjectDir, opts.PluginsDir)
	}

	nameKey := strings.ToLower(strings.TrimSpace(name))
	allGoPath := filepath.Join(opts.PluginsDir, "all", "all.go")
	_ = unregisterFromAllGo(allGoPath, nameKey)

	targetDir := filepath.Join(opts.PluginsDir, nameKey)
	_ = os.RemoveAll(targetDir)

	_ = removeInstalledEntry(opts.ProjectDir, nameKey)

	if !opts.NoBuild {
		buildCmd := exec.Command("go", "build", "-o", "tcp-warden", ".")
		buildCmd.Dir = opts.ProjectDir
		if err := buildCmd.Run(); err == nil {
			updateInstalledExecutable(filepath.Join(opts.ProjectDir, "tcp-warden"))
		}
	}

	return nil
}

func saveInstalledEntry(projectDir string, entry InstalledPluginEntry) error {
	projectDir = ResolveProjectDir(projectDir)
	regPath := filepath.Join(projectDir, "plugins.json")
	var reg installedRegistry

	if data, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	updated := false
	for i, e := range reg.Installed {
		if strings.EqualFold(e.Name, entry.Name) {
			reg.Installed[i] = entry
			updated = true
			break
		}
	}
	if !updated {
		reg.Installed = append(reg.Installed, entry)
	}

	bytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, bytes, 0644)
}

func removeInstalledEntry(projectDir string, name string) error {
	projectDir = ResolveProjectDir(projectDir)
	regPath := filepath.Join(projectDir, "plugins.json")
	var reg installedRegistry

	data, err := os.ReadFile(regPath)
	if err != nil {
		return nil
	}
	_ = json.Unmarshal(data, &reg)

	filtered := []InstalledPluginEntry{}
	for _, e := range reg.Installed {
		if !strings.EqualFold(e.Name, name) {
			filtered = append(filtered, e)
		}
	}
	reg.Installed = filtered

	var newEnabled []string
	for _, item := range reg.Enabled {
		if !strings.EqualFold(item, name) {
			newEnabled = append(newEnabled, item)
		}
	}
	reg.Enabled = newEnabled

	var newDisabled []string
	for _, item := range reg.Disabled {
		if !strings.EqualFold(item, name) {
			newDisabled = append(newDisabled, item)
		}
	}
	reg.Disabled = newDisabled

	bytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, bytes, 0644)
}

// GetInstalledRegistry loads plugins.json if available.
func GetInstalledRegistry(projectDir string) ([]InstalledPluginEntry, error) {
	projectDir = ResolveProjectDir(projectDir)
	regPath := filepath.Join(projectDir, "plugins.json")
	data, err := os.ReadFile(regPath)
	if err != nil {
		return nil, nil
	}
	var reg installedRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, err
	}
	return reg.Installed, nil
}

// SavePluginEnablement persists the enabled/disabled state of a plugin to plugins.json.
func SavePluginEnablement(projectDir string, name string, enabled bool) error {
	projectDir = ResolveProjectDir(projectDir)
	regPath := filepath.Join(projectDir, "plugins.json")
	var reg installedRegistry

	if data, err := os.ReadFile(regPath); err == nil {
		_ = json.Unmarshal(data, &reg)
	}

	name = strings.ToLower(strings.TrimSpace(name))

	// Remove from both lists first
	var newEnabled []string
	for _, item := range reg.Enabled {
		if !strings.EqualFold(item, name) {
			newEnabled = append(newEnabled, item)
		}
	}
	var newDisabled []string
	for _, item := range reg.Disabled {
		if !strings.EqualFold(item, name) {
			newDisabled = append(newDisabled, item)
		}
	}

	if enabled {
		newEnabled = append(newEnabled, name)
	} else {
		newDisabled = append(newDisabled, name)
	}

	reg.Enabled = newEnabled
	reg.Disabled = newDisabled

	bytes, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(regPath, bytes, 0644)
}

// GetPluginEnablement returns lists of enabled and disabled plugins from plugins.json.
func GetPluginEnablement(projectDir string) ([]string, []string, error) {
	projectDir = ResolveProjectDir(projectDir)
	regPath := filepath.Join(projectDir, "plugins.json")
	data, err := os.ReadFile(regPath)
	if err != nil {
		return nil, nil, nil
	}
	var reg installedRegistry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, nil, err
	}
	return reg.Enabled, reg.Disabled, nil
}

// copyDir copies a directory recursively.
func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if entry.Name() == ".git" {
				continue
			}
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

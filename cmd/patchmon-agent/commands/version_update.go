package commands

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"patchmon-agent/internal/config"
	"patchmon-agent/internal/version"

	"github.com/spf13/cobra"
)

const (
	serverTimeout       = 30 * time.Second
	versionCheckTimeout = 10 * time.Second // Shorter timeout for version checks
)

type ServerVersionResponse struct {
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	Size         int64  `json:"size"`
	Hash         string `json:"hash"`
	DownloadURL  string `json:"downloadUrl"`
	BinaryData   []byte `json:"-"` // Binary data (not serialized to JSON)
}

type ServerVersionInfo struct {
	CurrentVersion         string   `json:"currentVersion"`
	LatestVersion          string   `json:"latestVersion"`
	HasUpdate              bool     `json:"hasUpdate"`
	LastChecked            string   `json:"lastChecked"`
	SupportedArchitectures []string `json:"supportedArchitectures"`
}

// checkVersionCmd represents the check-version command
var checkVersionCmd = &cobra.Command{
	Use:   "check-version",
	Short: "Check for agent updates",
	Long:  "Check if there are any updates available for the PatchMon agent.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkRoot(); err != nil {
			return err
		}

		return checkVersion()
	},
}

// updateAgentCmd represents the update-agent command
var updateAgentCmd = &cobra.Command{
	Use:   "update-agent",
	Short: "Update agent to latest version",
	Long:  "Download and install the latest version of the PatchMon agent.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := checkRoot(); err != nil {
			return err
		}

		return updateAgent()
	},
}

func checkVersion() error {
	logger.Info("Checking for agent updates...")

	versionInfo, err := getServerVersionInfo()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	currentVersion := strings.TrimPrefix(version.Version, "v")
	latestVersion := strings.TrimPrefix(versionInfo.LatestVersion, "v")

	if versionInfo.HasUpdate {
		logger.Info("Agent update available!")
		fmt.Printf("  Current version: %s\n", currentVersion)
		fmt.Printf("  Latest version: %s\n", latestVersion)
		fmt.Printf("\nTo update, run: patchmon-agent update-agent\n")
	} else {
		logger.WithField("version", currentVersion).Info("Agent is up to date")
		fmt.Printf("Agent is up to date (version %s)\n", currentVersion)
	}

	return nil
}

func updateAgent() error {
	logger.Info("Updating agent...")

	// Get current executable path
	executablePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks to get the actual binary path (important for Alpine and other systems)
	// This ensures we update the actual file, not just a symlink
	resolvedPath, err := filepath.EvalSymlinks(executablePath)
	if err != nil {
		logger.WithError(err).WithField("path", executablePath).Warn("Could not resolve symlinks, using original path")
		resolvedPath = executablePath
	} else if resolvedPath != executablePath {
		logger.WithField("original", executablePath).WithField("resolved", resolvedPath).Debug("Resolved executable symlink")
		executablePath = resolvedPath
	}

	// Get current version for comparison
	currentVersion := strings.TrimPrefix(version.Version, "v")

	// First, check server version info to see if update is needed
	logger.Debug("Checking server for latest version...")
	versionInfo, err := getServerVersionInfo()
	if err != nil {
		logger.WithError(err).Warn("Failed to get version info, proceeding with update anyway")
	} else {
		latestVersion := strings.TrimPrefix(versionInfo.LatestVersion, "v")
		logger.WithField("current", currentVersion).WithField("latest", latestVersion).Debug("Version check")

		// Check if update is actually needed
		if currentVersion == latestVersion && !versionInfo.HasUpdate {
			logger.WithField("version", currentVersion).Info("Agent is already at the latest version, skipping update")
			return nil
		}
	}

	// Get latest binary info from server
	binaryInfo, err := getLatestBinaryFromServer()
	if err != nil {
		return fmt.Errorf("failed to get latest binary information: %w", err)
	}

	newAgentData := binaryInfo.BinaryData
	if len(newAgentData) == 0 {
		return fmt.Errorf("no binary data received from server")
	}

	// Get the new version from server version info (more reliable than parsing binary output)
	newVersion := currentVersion // Default to current if we can't determine
	if versionInfo != nil && versionInfo.LatestVersion != "" {
		newVersion = strings.TrimPrefix(versionInfo.LatestVersion, "v")
	}

	logger.WithField("current", currentVersion).WithField("new", newVersion).Info("Proceeding with update")
	logger.Info("Using downloaded agent binary...")

	// Create backup of current executable
	backupPath := fmt.Sprintf("%s.backup.%s", executablePath, time.Now().Format("20060102_150405"))
	if err := copyFile(executablePath, backupPath); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	logger.WithField("path", backupPath).Info("Backup saved")

	// Write new version to temporary file (reuse the temp file we already created for version check)
	tempPath := executablePath + ".new"
	if err := os.WriteFile(tempPath, newAgentData, 0755); err != nil {
		return fmt.Errorf("failed to write new agent: %w", err)
	}

	// Verify the new executable works
	logger.Debug("Validating new executable...")
	testCmd := exec.Command(tempPath, "check-version")
	testCmd.Env = os.Environ() // Preserve environment variables
	if err := testCmd.Run(); err != nil {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			logger.WithError(removeErr).Warn("Failed to remove temporary file after validation failure")
		}
		return fmt.Errorf("new agent executable is invalid: %w", err)
	}
	logger.Debug("New executable validation passed")

	// Replace current executable atomically
	// On Linux, we can rename over a running executable - the old process keeps using the old inode
	// When the service restarts, it will use the new binary
	logger.Debug("Replacing executable atomically...")
	if err := os.Rename(tempPath, executablePath); err != nil {
		if removeErr := os.Remove(tempPath); removeErr != nil {
			logger.WithError(removeErr).Warn("Failed to remove temporary file after rename failure")
		}
		// Check if it's a filesystem/permission issue
		if os.IsPermission(err) {
			return fmt.Errorf("failed to replace executable (permission denied): %w. Ensure the binary is writable", err)
		}
		return fmt.Errorf("failed to replace executable: %w", err)
	}

	// Ensure the new binary has correct permissions (in case umask affected it)
	if err := os.Chmod(executablePath, 0755); err != nil {
		logger.WithError(err).Warn("Failed to set executable permissions on new binary")
		// Don't fail the update for this, but log it
	}

	logger.WithField("version", binaryInfo.Version).Info("Agent updated successfully")

	// Restart the service to pick up the new binary
	// This is critical - the old process is still running the old binary
	logger.Info("Restarting patchmon-agent service to load new binary...")
	if err := restartService(); err != nil {
		logger.WithError(err).Error("Failed to restart service - new binary is in place but old process is still running")
		logger.Warn("Manual service restart required to complete update")
		return fmt.Errorf("update completed but service restart failed: %w", err)
	} else {
		logger.Info("Service restarted successfully - new binary is now active")
	}

	// Send updated information to PatchMon
	logger.Info("Sending updated information to PatchMon...")
	if err := sendReport(); err != nil {
		logger.WithError(err).Warn("Failed to send updated information to PatchMon (this is not critical)")
	} else {
		logger.Info("Successfully sent updated information to PatchMon")
	}

	return nil
}

// getServerVersionInfo fetches version information from the PatchMon server
func getServerVersionInfo() (*ServerVersionInfo, error) {
	cfgManager := config.New()
	if err := cfgManager.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	cfg := cfgManager.GetConfig()

	// Load credentials for API authentication
	if err := cfgManager.LoadCredentials(); err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}
	credentials := cfgManager.GetCredentials()

	architecture := getArchitecture()
	currentVersion := strings.TrimPrefix(version.Version, "v")
	url := fmt.Sprintf("%s/api/v1/hosts/agent/version?arch=%s&type=go&currentVersion=%s", cfg.PatchmonServer, architecture, currentVersion)

	ctx, cancel := context.WithTimeout(context.Background(), versionCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", fmt.Sprintf("patchmon-agent/%s", version.Version))
	req.Header.Set("X-API-ID", credentials.APIID)
	req.Header.Set("X-API-KEY", credentials.APIKey)

	// Create HTTP client with proper timeouts (shorter for version checks)
	httpClient := &http.Client{
		Timeout: versionCheckTimeout,
		Transport: &http.Transport{
			ResponseHeaderTimeout: 5 * time.Second,
		},
	}

	// Configure for insecure SSL if needed
	if cfg.SkipSSLVerify {
		httpClient.Transport = &http.Transport{
			ResponseHeaderTimeout: 5 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.WithError(closeErr).Debug("Failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var versionInfo ServerVersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&versionInfo); err != nil {
		return nil, fmt.Errorf("failed to decode version info: %w", err)
	}

	return &versionInfo, nil
}

// getLatestBinaryFromServer fetches the latest binary information from the PatchMon server
func getLatestBinaryFromServer() (*ServerVersionResponse, error) {
	cfgManager := config.New()
	if err := cfgManager.LoadConfig(); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}
	cfg := cfgManager.GetConfig()

	// Load credentials for API authentication
	if err := cfgManager.LoadCredentials(); err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}
	credentials := cfgManager.GetCredentials()

	architecture := getArchitecture()
	url := fmt.Sprintf("%s/api/v1/hosts/agent/download?arch=%s", cfg.PatchmonServer, architecture)

	ctx, cancel := context.WithTimeout(context.Background(), serverTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", fmt.Sprintf("patchmon-agent/%s", version.Version))
	req.Header.Set("X-API-ID", credentials.APIID)
	req.Header.Set("X-API-KEY", credentials.APIKey)

	// Configure HTTP client for insecure SSL if needed
	httpClient := http.DefaultClient
	if cfg.SkipSSLVerify {
		logger.Warn("⚠️  SSL certificate verification is disabled for binary download")
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			logger.WithError(closeErr).Debug("Failed to close response body")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	// Read the binary data
	binaryData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read binary data: %w", err)
	}

	// Calculate hash
	hash := fmt.Sprintf("%x", sha256.Sum256(binaryData))

	return &ServerVersionResponse{
		Version:      version.Version, // We'll get the actual version from the server later
		Architecture: architecture,
		Size:         int64(len(binaryData)),
		Hash:         hash,
		DownloadURL:  url,
		BinaryData:   binaryData, // Store the binary data directly
	}, nil
}

// getArchitecture returns the architecture string for the current platform
func getArchitecture() string {
	return runtime.GOARCH
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	return os.WriteFile(dst, data, 0755)
}

// restartService restarts the patchmon-agent service (supports systemd and OpenRC)
func restartService() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Detect init system and use appropriate restart command
	if _, err := exec.LookPath("systemctl"); err == nil {
		// Systemd is available
		logger.Debug("Detected systemd, using systemctl restart")
		cmd := exec.CommandContext(ctx, "systemctl", "restart", "patchmon-agent")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to restart service: %w, output: %s", err, string(output))
		}
		logger.WithField("output", string(output)).Debug("Service restart command completed")
		return nil
	} else if _, err := exec.LookPath("rc-service"); err == nil {
		// OpenRC is available (Alpine Linux)
		// Since we're running inside the service, we can't stop ourselves directly
		// Instead, we'll create a helper script that runs after we exit
		logger.Debug("Detected OpenRC, scheduling service restart via helper script")

		// Create a helper script that will restart the service after we exit
		helperScript := `#!/bin/sh
# Wait a moment for the current process to exit
sleep 2
# Restart the service
rc-service patchmon-agent restart 2>&1 || rc-service patchmon-agent start 2>&1
# Clean up this script
rm -f "$0"
`
		helperPath := "/etc/patchmon/patchmon-restart-helper.sh"
		if err := os.WriteFile(helperPath, []byte(helperScript), 0755); err != nil {
			logger.WithError(err).Warn("Failed to create restart helper script, will exit and rely on OpenRC auto-restart")
			// Fall through to exit approach
		} else {
			// Execute the helper script in background (detached from current process)
			// Use 'sh -c' with nohup to ensure it runs after we exit
			cmd := exec.Command("sh", "-c", fmt.Sprintf("nohup %s > /dev/null 2>&1 &", helperPath))
			if err := cmd.Start(); err != nil {
				logger.WithError(err).Warn("Failed to start restart helper script, will exit and rely on OpenRC auto-restart")
				// Clean up script
				os.Remove(helperPath)
				// Fall through to exit approach
			} else {
				logger.Info("Scheduled service restart via helper script, exiting now...")
				// Give the helper script a moment to start
				time.Sleep(500 * time.Millisecond)
				// Exit gracefully - the helper script will restart the service
				os.Exit(0)
			}
		}

		// Fallback: If helper script approach failed, just exit and let OpenRC handle it
		// OpenRC with command_background="yes" should restart on exit
		logger.Info("Exiting to allow OpenRC to restart service with new binary...")
		os.Exit(0)
		// os.Exit never returns, but we need this for code flow
		return nil
	} else {
		// Fallback: try to kill and let service manager restart it
		logger.Warn("No known init system detected, attempting to restart via process signal")
		// Try to find and kill the process, service manager should restart it
		killCmd := exec.CommandContext(ctx, "pkill", "-HUP", "patchmon-agent")
		if err := killCmd.Run(); err != nil {
			return fmt.Errorf("failed to restart service: no init system detected and pkill failed: %w", err)
		}
		logger.Info("Sent HUP signal to agent process")
		return nil
	}
}

// Removed update-crontab command (cron is no longer used)

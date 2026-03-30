// Package downloader provides file download functionality for CipherSwarm resources.
package downloader

import (
	"context"
	"crypto/md5" //nolint:gosec // G501 - checksum verification // DevSkim: ignore DS126858
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cavaliergopher/grab/v3"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/progress"
)

const (
	progressPollInterval = 200 * time.Millisecond // Polling interval for download progress updates
)

// Getter is an interface that abstracts the download operation, allowing for
// easier testing through mocks without requiring actual network downloads.
type Getter interface {
	Get() error
}

// DownloadFile downloads a file from a given URL and saves it to the specified path with optional checksum verification.
// If the URL is invalid, it returns an error. If the file already exists and the checksum matches, the download is skipped.
func DownloadFile(ctx context.Context, fileURL, filePath, checksum string) error {
	parsedURL, err := url.Parse(fileURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		agentstate.Logger.Error("Invalid URL", "url", fileURL)
		return errors.New("invalid URL")
	}

	if FileExistsAndValid(filePath, checksum) {
		agentstate.Logger.Info("Download already exists", "path", filePath)
		return nil
	}

	if err := downloadAndVerifyFile(ctx, fileURL, filePath, checksum); err != nil {
		return err
	}

	return nil
}

// FileExistsAndValid checks if a file exists at the given path and, if a checksum is provided, verifies its validity.
// The function returns true if the file exists and matches the given checksum, or if no checksum is provided
// and the file is non-empty. If the file does not exist or the checksum verification fails, appropriate error
// messages are logged.
func FileExistsAndValid(filePath, checksum string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			agentstate.Logger.Error("Error checking file existence", "path", filePath, "error", err)
		}

		return false
	}

	if strings.TrimSpace(checksum) == "" {
		if info.Size() == 0 {
			agentstate.Logger.Warn("Existing file is empty, will re-download", "path", filePath)

			return false
		}

		return true
	}

	fileChecksum, err := fileMD5(filePath) // DevSkim: ignore DS126858
	if err != nil {
		agentstate.Logger.Error("Error calculating file checksum", "path", filePath, "error", err)

		return false
	}

	if fileChecksum == checksum {
		return true
	}

	agentstate.Logger.Warn(
		"Checksums do not match",
		"path",
		filePath,
		"url_checksum",
		checksum,
		"file_checksum",
		fileChecksum,
	)

	if err := os.Remove(filePath); err != nil {
		agentstate.Logger.Error("Error removing file with mismatched checksum", "path", filePath, "error", err)
	}

	return false
}

// grabDownloader wraps a single download attempt using grab.Client,
// implementing the Getter interface to plug into downloadWithRetry.
type grabDownloader struct {
	client   *grab.Client
	ctx      context.Context //nolint:containedctx // context is part of the download lifecycle
	url      string
	dst      string
	checksum string
	tracker  progress.Tracker
}

// Get performs one complete download attempt with progress tracking.
func (g *grabDownloader) Get() error {
	req, err := grab.NewRequest(g.dst, g.url)
	if err != nil {
		return fmt.Errorf("creating download request: %w", err)
	}

	req = req.WithContext(g.ctx)

	if g.checksum != "" {
		checksumBytes, decErr := hex.DecodeString(g.checksum)
		if decErr != nil {
			return fmt.Errorf("decoding checksum: %w", decErr)
		}
		//nolint:gosec // G401 - MD5 used for file integrity check, not security
		req.SetChecksum(md5.New(), checksumBytes, true) // DevSkim: ignore DS126858
	}

	resp := g.client.Do(req)
	dp := g.tracker.StartTracking(g.url, resp.Size())

	ticker := time.NewTicker(progressPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dp.Update(resp.BytesComplete())

			if resp.IsComplete() {
				dp.Update(resp.BytesComplete())
				dp.Finish()

				if err := resp.Err(); err != nil {
					return fmt.Errorf("downloading %s: %w", g.url, err)
				}

				return nil
			}
		case <-g.ctx.Done():
			// Wait for Grab to finalize the transfer (close body, flush writer)
			// before returning. resp.Err() blocks until resp.Done is closed.
			err := resp.Err()
			dp.Update(resp.BytesComplete())
			dp.Finish()

			if err != nil {
				return fmt.Errorf("downloading %s: %w", g.url, err)
			}

			return g.ctx.Err()
		}
	}
}

// downloadAndVerifyFile downloads a file from the given URL and saves it to the specified path.
// Uses grab/v3 for the actual download with native checksum verification.
// Uses retry logic for transient failures.
func downloadAndVerifyFile(ctx context.Context, fileURL, filePath, checksum string) error {
	insecure := agentstate.State.InsecureDownloads
	if insecure {
		agentstate.Logger.Warn("TLS certificate verification disabled for download",
			"url", fileURL, "dst", filePath)
	}

	grabClient := grab.NewClient()
	if insecure {
		if err := applyInsecureTransport(grabClient); err != nil {
			return fmt.Errorf("insecure download mode configured but cannot be applied: %w", err)
		}
	}

	dl := &grabDownloader{
		client:   grabClient,
		ctx:      ctx,
		url:      fileURL,
		dst:      filePath,
		checksum: strings.TrimSpace(checksum),
		tracker:  progress.DefaultProgressBar,
	}

	maxRetries := agentstate.State.DownloadMaxRetries
	baseDelay := agentstate.State.DownloadRetryDelay

	if err := downloadWithRetry(ctx, dl, maxRetries, baseDelay); err != nil {
		return err
	}

	if strings.TrimSpace(checksum) != "" && !FileExistsAndValid(filePath, checksum) {
		return errors.New("downloaded file checksum does not match")
	}

	return nil
}

// applyInsecureTransport disables TLS certificate verification on the grab client's
// HTTP transport. Returns an error if the transport chain cannot be unwrapped, ensuring
// the caller never silently falls back to secure TLS when insecure mode was requested.
func applyInsecureTransport(grabClient *grab.Client) error {
	httpClient, ok := grabClient.HTTPClient.(*http.Client)
	if !ok {
		return fmt.Errorf("unexpected HTTP client type %T", grabClient.HTTPClient)
	}

	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("unexpected transport type %T", httpClient.Transport)
	}

	cloned := transport.Clone()
	//nolint:gosec // G402 - user-configured insecure download mode
	cloned.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpClient.Transport = cloned

	return nil
}

// downloadWithRetry attempts to download a file with exponential backoff retry logic.
// It retries up to maxRetries times, with delays doubling after each failed attempt.
// The ctx parameter enables context-aware sleep between retries, returning immediately
// on cancellation instead of blocking for the full delay.
func downloadWithRetry(ctx context.Context, client Getter, maxRetries int, baseDelay time.Duration) error {
	// Ensure at least one download attempt is made
	if maxRetries < 1 {
		agentstate.Logger.Warn("maxRetries value < 1, defaulting to 1 attempt",
			"configured_value", maxRetries)
		maxRetries = 1
	}

	var lastErr error

	for attempt := range maxRetries {
		if attempt > 0 {
			// Exponential backoff: baseDelay * 2^(attempt-1)
			delay := baseDelay * time.Duration(1<<(attempt-1))
			agentstate.Logger.Debug("Retrying download", "attempt", attempt+1, "delay", delay)

			timer := time.NewTimer(delay)

			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()

				if lastErr != nil {
					return fmt.Errorf(
						"download cancelled after %d attempt(s) (last error: %w): %w",
						attempt, lastErr, ctx.Err())
				}

				return fmt.Errorf("download cancelled: %w", ctx.Err())
			}
		}

		if err := client.Get(); err != nil {
			lastErr = err
			agentstate.Logger.Warn("Download attempt failed", "attempt", attempt+1, "error", err)

			continue
		}

		return nil
	}

	agentstate.Logger.Error("All download attempts failed", "attempts", maxRetries, "error", lastErr)

	return lastErr
}

// DownloadHashList downloads the hash list for a given attack.
// It constructs the local path for the hash list file and attempts to remove any existing file at that location.
// The function makes an API call to fetch the hash list, checks the response status, and handles errors if the call fails.
// If the response stream is not nil, it writes the hash list to the file and verifies the downloaded file is non-empty.
// Logs relevant actions and errors encountered during the process and returns any errors that occur.
func DownloadHashList(ctx context.Context, attack *api.Attack) error {
	if attack == nil {
		return errors.New("attack is nil")
	}

	hashlistPath := filepath.Join(agentstate.State.HashlistPath, fmt.Sprintf("%d.hsh", attack.Id))
	agentstate.Logger.Debug("Downloading hash list", "url", attack.HashListUrl, "path", hashlistPath)

	if err := removeExistingFile(hashlistPath); err != nil {
		return err
	}

	response, err := agentstate.State.GetAPIClient().Attacks().GetHashList(ctx, attack.Id)
	if err != nil {
		return fmt.Errorf("error downloading hashlist from the CipherSwarm API: %w", err)
	}

	if response.StatusCode() != http.StatusOK {
		return fmt.Errorf("error downloading hashlist: %s", response.Status())
	}

	responseStream := api.HashListResponseStream(response)
	if responseStream == nil {
		return errors.New("response stream is nil")
	}

	if err := writeResponseToFile(responseStream, hashlistPath); err != nil {
		return err
	}

	downloadSize, err := os.Stat(hashlistPath)
	if err != nil {
		return fmt.Errorf("could not stat downloaded hash list: %w", err)
	}
	if downloadSize.Size() == 0 {
		return errors.New("downloaded hash list is empty")
	}

	agentstate.Logger.Debug("Downloaded hash list", "path", hashlistPath)

	return nil
}

// Base64ToHex converts a base64 encoded string to a hexadecimal string.
// Returns an error if the base64 input is invalid.
func Base64ToHex(b64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decoding base64 checksum: %w", err)
	}

	return hex.EncodeToString(data), nil
}

// removeExistingFile removes the file at filePath if it exists.
// Uses os.Remove directly to avoid TOCTOU races.
// Returns an error if removal fails for reasons other than the file not existing.
func removeExistingFile(filePath string) error {
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error removing old file %s: %w", filePath, err)
	}

	return nil
}

// writeResponseToFile writes the data from an io.Reader (responseStream) to a file specified by the filePath.
// Creates a new file at the given path, writes the response stream to it, and handles errors accordingly.
func writeResponseToFile(responseStream io.Reader, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}

	if _, err := io.Copy(file, responseStream); err != nil {
		_ = file.Close()
		return fmt.Errorf("error writing file: %w", err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("error closing file %s: %w", filePath, err)
	}

	return nil
}

// fileMD5 computes the MD5 hex digest of the file at the given path.
// MD5 is used because the CipherSwarm server provides MD5 checksums in its API.
// This is for integrity verification (bit-flip detection), not cryptographic security.
// Migration to SHA-256 requires a server-side API change.
func fileMD5(filePath string) (string, error) { // DevSkim: ignore DS126858
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	defer func() {
		if cerr := f.Close(); cerr != nil {
			agentstate.Logger.Error("Error closing file after checksum",
				"path", filePath, "error", cerr)
		}
	}()

	h := md5.New() //nolint:gosec // G401 - MD5 used for file integrity check, not security // DevSkim: ignore DS126858
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// CleanupTempDir removes the specified temporary directory and its contents.
// It logs any errors encountered during the removal process.
func CleanupTempDir(tempDir string) error {
	if err := os.RemoveAll(tempDir); err != nil {
		agentstate.Logger.Error("Error removing temporary directory", "path", tempDir, "error", err)
		return err
	}

	return nil
}

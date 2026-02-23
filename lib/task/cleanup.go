package task

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
)

// CleanupTaskFiles removes task-related files (hash list and restore file) for the given attack ID.
// It is used to clean up files when a task fails before a hashcat session is created,
// since Session.Cleanup() is not available in those code paths.
// Resource files (word lists, rule lists, mask lists) are intentionally NOT cleaned here
// because they are shared across attacks and may be reused via checksum-based caching.
// It is idempotent — files already removed (e.g., by Session.Cleanup) are silently skipped.
// Errors during removal are logged but do not halt the cleanup process.
func CleanupTaskFiles(attackID int64) {
	id := strconv.FormatInt(attackID, 10)

	removeTaskFile := func(filePath string) {
		if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
			agentstate.Logger.Error("couldn't remove task file", "file", filePath, "error", err)
		}
	}

	hashFile := filepath.Join(agentstate.State.HashlistPath, id+".hsh")
	removeTaskFile(hashFile)

	restoreFile := filepath.Join(agentstate.State.RestoreFilePath, id+".restore")
	removeTaskFile(restoreFile)
}

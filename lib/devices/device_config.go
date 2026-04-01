package devices

import (
	"strconv"
	"strings"
)

// DeviceConfig encapsulates device selection state for hashcat sessions.
// It holds the server-provided or CLI-provided raw strings and an optional
// DeviceManager for validation. Constructed via NewDeviceConfig.
//
// DeviceConfig is a value type — safe to copy across goroutines.
// The embedded DeviceManager pointer is read-only after creation.
type DeviceConfig struct {
	rawBackendDevices string
	rawOpenCLDevices  string
	dm                *DeviceManager
	enabledIDs        []int
	validated         bool // true when dm was non-nil at construction time
}

// NewDeviceConfig creates a DeviceConfig from server/CLI strings and an
// optional DeviceManager. When dm is non-nil, the raw backend device string
// is parsed and validated against the enumerated devices. When dm is nil,
// the raw strings are preserved for best-effort forwarding to hashcat.
func NewDeviceConfig(rawBackend, rawOpenCL string, dm *DeviceManager) DeviceConfig {
	dc := DeviceConfig{
		rawBackendDevices: rawBackend,
		rawOpenCLDevices:  rawOpenCL,
		dm:                dm,
		validated:         dm != nil,
	}

	// Parse raw backend string into IDs regardless of dm state.
	// When dm is nil, these IDs are forwarded without validation.
	ids, err := parseDeviceIDString(rawBackend)
	if err == nil && len(ids) > 0 {
		dc.enabledIDs = ids
	}

	return dc
}

// ResolvedBackendDevices returns the --backend-devices flag value using
// 3-tier resolution:
//  1. Validated IDs (if dm was provided and IDs are valid)
//  2. Empty string (if dm was provided but all IDs were invalid — let hashcat auto-detect)
//  3. Raw server string (if dm was nil — best-effort forwarding)
func (dc DeviceConfig) ResolvedBackendDevices() string {
	if !dc.validated {
		// No DeviceManager — forward raw server string as-is.
		return strings.TrimSpace(dc.rawBackendDevices)
	}

	if len(dc.enabledIDs) == 0 {
		// No IDs configured — let hashcat use all devices.
		return ""
	}

	// Validate IDs against the device manager.
	validation := dc.dm.ValidateDeviceIDsDetailed(dc.enabledIDs)
	if len(validation.ValidIDs) == 0 {
		// All configured IDs were invalid — let hashcat auto-detect.
		return ""
	}

	return intsToCSV(validation.ValidIDs)
}

// ResolvedOpenCLDevices returns the --opencl-device-types flag value.
func (dc DeviceConfig) ResolvedOpenCLDevices() string {
	return strings.TrimSpace(dc.rawOpenCLDevices)
}

// Validate runs device ID validation against the DeviceManager and returns
// the filtered result. Logs warnings for unknown/unavailable IDs via
// logWarnFn. Returns an empty ValidatedDevices when dm is nil or no IDs
// are configured.
func (dc DeviceConfig) Validate(logWarnFn func(msg any, keyvals ...any)) ValidatedDevices {
	result := ValidatedDevices{
		OpenCLDeviceTypes: strings.TrimSpace(dc.rawOpenCLDevices),
	}

	if dc.dm == nil || len(dc.enabledIDs) == 0 {
		return result
	}

	validation := dc.dm.ValidateDeviceIDsDetailed(dc.enabledIDs)

	for _, id := range validation.UnknownIDs {
		logWarnFn("Backend device ID not found in enumerated devices, skipping",
			"device_id", id)
	}

	for _, id := range validation.UnavailableIDs {
		logWarnFn("Backend device ID is unavailable/skipped, excluding from session",
			"device_id", id)
	}

	result.BackendDeviceIDs = validation.ValidIDs

	return result
}

// DeviceManager returns the underlying DeviceManager, or nil if enumeration
// was not performed. Callers should use this for device name lookups and
// capability queries — not for validation (use Validate instead).
func (dc DeviceConfig) DeviceManager() *DeviceManager {
	return dc.dm
}

// RawBackendDevices returns the original server-sent or CLI-provided
// backend device string. Used for logging and diagnostics.
func (dc DeviceConfig) RawBackendDevices() string {
	return dc.rawBackendDevices
}

// RawOpenCLDevices returns the original server-sent or CLI-provided
// OpenCL device type string. Used for logging and diagnostics.
func (dc DeviceConfig) RawOpenCLDevices() string {
	return dc.rawOpenCLDevices
}

// intsToCSV converts a slice of ints to a comma-separated string.
func intsToCSV(ids []int) string {
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}

	return strings.Join(parts, ",")
}

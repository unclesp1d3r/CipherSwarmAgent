package devices

import (
	"fmt"
	"strconv"
	"strings"
)

// ValidateDeviceIDString parses a comma-separated string of device IDs and
// validates each against the enumerated device set. Returns the parsed IDs
// and nil on success, (nil, nil) when raw is empty, or a wrapped
// ErrInvalidDeviceID when any ID is not in the enumerated set.
// Non-numeric tokens produce a parse error.
func ValidateDeviceIDString(dm *DeviceManager, raw string) ([]int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	tokens := strings.Split(trimmed, ",")
	ids := make([]int, 0, len(tokens))

	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}

		id, err := strconv.Atoi(tok)
		if err != nil {
			return nil, fmt.Errorf("non-numeric device ID %q: %w", tok, err)
		}

		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	if err := dm.ValidateDeviceIDs(ids); err != nil {
		return nil, err
	}

	return ids, nil
}

// parseDeviceIDString parses a comma-separated string of device IDs into an
// int slice. Returns (nil, nil) when raw is empty.
func parseDeviceIDString(raw string) ([]int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, nil
	}

	tokens := strings.Split(trimmed, ",")
	ids := make([]int, 0, len(tokens))

	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}

		id, err := strconv.Atoi(tok)
		if err != nil {
			return nil, fmt.Errorf("non-numeric device ID %q: %w", tok, err)
		}

		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return nil, nil
	}

	return ids, nil
}

// ValidatedDevices holds the validated device selection for a hashcat session.
// BackendDeviceIDs contains only IDs that exist and are available.
// OpenCLDeviceTypes is the raw OpenCL device type string (not ID-validated).
type ValidatedDevices struct {
	BackendDeviceIDs  []int
	OpenCLDeviceTypes string
}

// BackendDevicesFlag returns the comma-separated string for --backend-devices,
// or empty string if no specific devices are selected.
func (vd ValidatedDevices) BackendDevicesFlag() string {
	if len(vd.BackendDeviceIDs) == 0 {
		return ""
	}

	parts := make([]string, len(vd.BackendDeviceIDs))
	for i, id := range vd.BackendDeviceIDs {
		parts[i] = strconv.Itoa(id)
	}

	return strings.Join(parts, ",")
}

// ValidateAndFilterDevices parses the raw device config strings, validates
// backend device IDs against the DeviceManager, and returns only the IDs that
// are known and available. Logs warnings for unknown and unavailable IDs via
// the provided log function. Returns an empty ValidatedDevices (use all devices)
// when dm is nil or rawBackendDevices is empty.
func ValidateAndFilterDevices(
	dm *DeviceManager,
	rawBackendDevices string,
	rawOpenCLDevices string,
	logWarnFn func(msg any, keyvals ...any),
) ValidatedDevices {
	result := ValidatedDevices{
		OpenCLDeviceTypes: strings.TrimSpace(rawOpenCLDevices),
	}

	if dm == nil || strings.TrimSpace(rawBackendDevices) == "" {
		return result
	}

	ids, err := parseDeviceIDString(rawBackendDevices)
	if err != nil {
		logWarnFn("Failed to parse backend device IDs, using all devices",
			"error", err, "raw_value", rawBackendDevices)

		return result
	}

	if len(ids) == 0 {
		return result
	}

	validation := dm.ValidateDeviceIDsDetailed(ids)

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

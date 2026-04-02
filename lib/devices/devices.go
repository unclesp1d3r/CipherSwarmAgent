// Package devices provides hashcat-native device enumeration via `hashcat -I`.
// It parses the text output to produce structured device information including
// backend type, vendor, and device classification.
package devices

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
)

var (
	// ErrNoDevicesFound is returned when hashcat -I produces no parseable device blocks.
	ErrNoDevicesFound = errors.New("no devices found in hashcat output")
	// ErrInvalidDeviceID is returned by ValidateDeviceIDs when an ID is not in the enumerated set.
	ErrInvalidDeviceID = errors.New("invalid device ID")
	// ErrUnavailableDeviceID is returned when a device ID exists but the device is unavailable.
	ErrUnavailableDeviceID = errors.New("unavailable device ID")
)

// Compile-time regex patterns for parsing hashcat -I output.
var (
	// backendAPIPattern matches section headers like "OpenCL Info:", "CUDA Info:", "Metal Info:", "HIP Info:".
	backendAPIPattern = regexp.MustCompile(`^(OpenCL|CUDA|Metal|HIP)\s+Info:`)
	// backendHeaderPattern matches lines like "Backend Device ID #1" to detect device blocks.
	backendHeaderPattern = regexp.MustCompile(`Backend Device ID #(\d+)`)
	// deviceNamePattern matches "Name...: <value>" lines.
	deviceNamePattern = regexp.MustCompile(`^\s+Name\.+:\s+(.+)$`)
	// deviceTypePattern matches "Type...: <value>" lines.
	deviceTypePattern = regexp.MustCompile(`^\s+Type\.+:\s+(.+)$`)
	// vendorPattern matches "Vendor...: <value>" lines but not "Vendor.ID" lines.
	vendorPattern = regexp.MustCompile(`^\s+Vendor\.+:\s+(.+)$`)
	// vendorIDPattern matches "Vendor.ID" lines so they can be skipped.
	vendorIDPattern = regexp.MustCompile(`Vendor\.ID`)
	// statusPattern matches "Status...: <value>" lines in hashcat -I output.
	statusPattern = regexp.MustCompile(`^\s+Status\.+:\s+(.+)$`)
	// skippedLinePattern matches standalone "* Device #N: Skipped" or "Skipped" lines
	// that hashcat emits for devices that failed initialization.
	skippedLinePattern = regexp.MustCompile(`(?i)^\s*\*?\s*Device\s+#\d+:\s+Skipped`)

	// Capability patterns for additional device properties from hashcat -I.
	processorsPattern    = regexp.MustCompile(`^\s+Processor\(s\)\.+:\s+(.+)$`)
	clockPattern         = regexp.MustCompile(`^\s+Clock\.+:\s+(.+)$`)
	memoryTotalPattern   = regexp.MustCompile(`^\s+Memory\.Total\.+:\s+(.+)$`)
	memoryFreePattern    = regexp.MustCompile(`^\s+Memory\.Free\.+:\s+(.+)$`)
	versionFieldPattern  = regexp.MustCompile(`^\s+Version\.+:\s+(.+)$`)
	driverVersionPattern = regexp.MustCompile(`^\s+Driver\.Version\.+:\s+(.+)$`)
	openCLVersionPattern = regexp.MustCompile(`^\s+OpenCL\.Version\.+:\s+(.+)$`)
)

// Capability key constants for Device.Capabilities map entries.
const (
	CapProcessors    = "processors"
	CapClock         = "clock"
	CapMemoryTotal   = "memory_total"
	CapMemoryFree    = "memory_free"
	CapVersion       = "version"
	CapDriverVersion = "driver_version"
	CapOpenCLVersion = "opencl_version"
)

// Device represents a single compute device enumerated by hashcat.
type Device struct {
	ID           int
	Name         string
	Type         string // "CPU" or "GPU"
	Backend      string // "OpenCL", "CUDA", "Metal", or "HIP"
	Vendor       string
	IsAvailable  bool
	Capabilities map[string]string // Optional capability fields parsed from hashcat -I output.
}

// CmdFactory creates an exec.Cmd for running hashcat with the given arguments.
// It exists to allow tests to inject a helper process binary.
type CmdFactory func(ctx context.Context, path string, args ...string) *exec.Cmd

// DeviceManager holds the enumerated devices and provides query methods.
type DeviceManager struct {
	devices    []Device
	cmdFactory CmdFactory // nil uses exec.CommandContext
}

// EnumerateDevices runs hashcat -I and parses the output to populate the device list.
// When hashcatPath is empty, it falls back to cracker.FindHashcatBinary() to resolve
// the binary path using the same discovery strategy as the rest of the agent.
func (dm *DeviceManager) EnumerateDevices(ctx context.Context, hashcatPath string) error {
	if hashcatPath == "" {
		resolved, err := cracker.FindHashcatBinary()
		if err != nil {
			return fmt.Errorf("resolve hashcat binary: %w", err)
		}

		hashcatPath = resolved
	}

	if err := arch.ValidateExecutablePath(hashcatPath); err != nil {
		return fmt.Errorf("validate hashcat path: %w", err)
	}

	makeCmd := dm.cmdFactory
	if makeCmd == nil {
		makeCmd = exec.CommandContext
	}

	out, err := makeCmd(ctx, hashcatPath, "-I").Output()
	if err != nil {
		return fmt.Errorf("execute hashcat -I: %w", err)
	}

	dm.devices = parseDeviceOutput(string(out))

	if len(dm.devices) == 0 {
		return ErrNoDevicesFound
	}

	agentstate.Logger.Debug("Enumerated devices", "count", len(dm.devices))

	return nil
}

// parseDeviceOutput parses the text output of hashcat -I into a slice of Device structs.
// It detects unavailable/skipped devices via "Status...: Skipped" lines or
// standalone "* Device #N: Skipped" lines and sets IsAvailable accordingly.
func parseDeviceOutput(output string) []Device {
	var (
		devs           []Device
		current        *Device
		currentBackend string
	)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		// Check for backend section headers.
		if matches := backendAPIPattern.FindStringSubmatch(line); len(matches) > 1 {
			currentBackend = matches[1]

			continue
		}

		// Check for standalone skipped-device lines (e.g., "* Device #3: Skipped").
		// These appear outside the device property block in some hashcat versions.
		if skippedLinePattern.MatchString(line) {
			if current != nil {
				current.IsAvailable = false
			}

			continue
		}

		// Check for device block start.
		if matches := backendHeaderPattern.FindStringSubmatch(line); len(matches) > 1 {
			// Flush previous device.
			if current != nil {
				devs = append(devs, *current)
			}

			id, err := strconv.Atoi(matches[1])
			if err != nil {
				agentstate.Logger.Warn("Failed to parse device ID, skipping device block",
					"raw_id", matches[1], "error", err)

				continue
			}

			current = &Device{
				ID:           id,
				Backend:      currentBackend,
				IsAvailable:  true,
				Capabilities: make(map[string]string),
			}

			continue
		}

		if current == nil {
			continue
		}

		// Parse device properties.
		if matches := deviceNamePattern.FindStringSubmatch(line); len(matches) > 1 {
			current.Name = strings.TrimSpace(matches[1])

			continue
		}

		if matches := deviceTypePattern.FindStringSubmatch(line); len(matches) > 1 {
			current.Type = strings.TrimSpace(matches[1])

			continue
		}

		// Check for device status (e.g., "Status...: Skipped").
		if matches := statusPattern.FindStringSubmatch(line); len(matches) > 1 {
			status := strings.TrimSpace(matches[1])
			if strings.EqualFold(status, "Skipped") {
				current.IsAvailable = false
			}

			continue
		}

		// Skip Vendor.ID lines before checking vendor.
		if vendorIDPattern.MatchString(line) {
			continue
		}

		if matches := vendorPattern.FindStringSubmatch(line); len(matches) > 1 {
			current.Vendor = strings.TrimSpace(matches[1])

			continue
		}

		// Parse capability properties into the Capabilities map.
		parseCapability(current, line)
	}

	// Flush last device.
	if current != nil {
		devs = append(devs, *current)
	}

	return devs
}

// capabilityPattern pairs a regex pattern with its Capabilities map key.
type capabilityPattern struct {
	pattern *regexp.Regexp
	key     string
}

// capabilityPatterns is the ordered list of capability patterns to try.
// Each match sets the corresponding key in Device.Capabilities.
var capabilityPatterns = []capabilityPattern{
	{processorsPattern, CapProcessors},
	{clockPattern, CapClock},
	{memoryTotalPattern, CapMemoryTotal},
	{memoryFreePattern, CapMemoryFree},
	{versionFieldPattern, CapVersion},
	{driverVersionPattern, CapDriverVersion},
	{openCLVersionPattern, CapOpenCLVersion},
}

// parseCapability attempts to match a line against all capability patterns
// and stores the first match in the device's Capabilities map.
func parseCapability(dev *Device, line string) {
	for _, cp := range capabilityPatterns {
		if matches := cp.pattern.FindStringSubmatch(line); len(matches) > 1 {
			dev.Capabilities[cp.key] = strings.TrimSpace(matches[1])

			return
		}
	}
}

// GetDevice returns the device with the given ID and whether it was found.
func (dm *DeviceManager) GetDevice(id int) (*Device, bool) {
	for i := range dm.devices {
		if dm.devices[i].ID == id {
			d := dm.devices[i]

			return &d, true
		}
	}

	return nil, false
}

// GetDevicesByType returns all devices matching the given type (case-insensitive).
func (dm *DeviceManager) GetDevicesByType(deviceType string) []Device {
	result := make([]Device, 0)
	upper := strings.ToUpper(deviceType)

	for _, d := range dm.devices {
		if strings.EqualFold(d.Type, upper) {
			result = append(result, d)
		}
	}

	return result
}

// GetAllDevices returns a shallow copy of all enumerated devices.
func (dm *DeviceManager) GetAllDevices() []Device {
	result := make([]Device, len(dm.devices))
	copy(result, dm.devices)

	return result
}

// ValidateDeviceIDs checks that all provided IDs exist in the enumerated device set.
func (dm *DeviceManager) ValidateDeviceIDs(ids []int) error {
	known := make(map[int]struct{}, len(dm.devices))
	for _, d := range dm.devices {
		known[d.ID] = struct{}{}
	}

	for _, id := range ids {
		if _, ok := known[id]; !ok {
			return fmt.Errorf("%w: %d", ErrInvalidDeviceID, id)
		}
	}

	return nil
}

// DeviceValidationResult holds the outcome of validating device IDs against
// the enumerated device set, separating valid, unknown, and unavailable IDs.
type DeviceValidationResult struct {
	ValidIDs       []int
	UnknownIDs     []int
	UnavailableIDs []int
}

// ValidateDeviceIDsDetailed checks each provided ID against the enumerated
// device set, classifying IDs as valid, unknown (not in set), or unavailable
// (in set but IsAvailable is false).
func (dm *DeviceManager) ValidateDeviceIDsDetailed(ids []int) DeviceValidationResult {
	deviceByID := make(map[int]*Device, len(dm.devices))
	for i := range dm.devices {
		deviceByID[dm.devices[i].ID] = &dm.devices[i]
	}

	result := DeviceValidationResult{
		ValidIDs:       make([]int, 0, len(ids)),
		UnknownIDs:     make([]int, 0),
		UnavailableIDs: make([]int, 0),
	}

	for _, id := range ids {
		dev, ok := deviceByID[id]
		if !ok {
			result.UnknownIDs = append(result.UnknownIDs, id)

			continue
		}

		if !dev.IsAvailable {
			result.UnavailableIDs = append(result.UnavailableIDs, id)

			continue
		}

		result.ValidIDs = append(result.ValidIDs, id)
	}

	return result
}

// GetAvailableDeviceIDs returns the IDs of all devices that are available.
func (dm *DeviceManager) GetAvailableDeviceIDs() []int {
	ids := make([]int, 0, len(dm.devices))
	for _, d := range dm.devices {
		if d.IsAvailable {
			ids = append(ids, d.ID)
		}
	}

	return ids
}

// HasDevices reports whether the manager has any enumerated devices.
func (dm *DeviceManager) HasDevices() bool {
	return len(dm.devices) > 0
}

package devices

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/agentstate"
	"github.com/unclesp1d3r/cipherswarmagent/lib/arch"
	"github.com/unclesp1d3r/cipherswarmagent/lib/cracker"
)

// TestHelperProcess is a helper process used by tests to avoid
// depending on OS-specific shell scripts. It is not a real test
// and exits immediately when invoked directly.
func TestHelperProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	output := os.Getenv("GO_HELPER_OUTPUT")
	if output != "" {
		fmt.Print(output)
	}

	exitCode := os.Getenv("GO_HELPER_EXIT_CODE")
	if exitCode == "1" {
		os.Exit(1)
	}

	os.Exit(0)
}

// helperCmdFactory returns a CmdFactory that invokes the test binary as a
// helper process, producing the given output on stdout. This replaces
// shell-script stubs for cross-platform compatibility.
func helperCmdFactory(output string) CmdFactory {
	return func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		//nolint:gosec // G204 - test helper uses os.Args[0]
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$")
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			"GO_HELPER_OUTPUT="+output,
		)

		return cmd
	}
}

// helperCmdFactoryExit returns a CmdFactory that invokes the test binary as
// a helper process that exits with code 1 (simulating hashcat failure).
func helperCmdFactoryExit() CmdFactory {
	return func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		//nolint:gosec // G204 - test helper uses os.Args[0]
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$")
		cmd.Env = append(os.Environ(),
			"GO_WANT_HELPER_PROCESS=1",
			"GO_HELPER_EXIT_CODE=1",
		)

		return cmd
	}
}

// newTestManager creates a DeviceManager with the given devices for accessor tests.
func newTestManager(devices []Device) *DeviceManager {
	return &DeviceManager{devices: devices}
}

const singleOpenCLGPU = `OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: NVIDIA Corporation
  Name....: NVIDIA CUDA
  Version.: OpenCL 3.0 CUDA 12.4.0

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 32
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce RTX 3090
    Version........: OpenCL 3.0
`

const multipleDevices = `OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: NVIDIA Corporation
  Name....: NVIDIA CUDA

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 32
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce RTX 3090

  Backend Device ID #2
    Type...........: CPU
    Vendor.ID......: 64
    Vendor.........: Intel Corporation
    Name...........: Intel Core i9-12900K
`

const cudaDevice = `CUDA Info:
==========

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 32
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce RTX 4090
`

const metalDevice = `Metal Info:
===========

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 0
    Vendor.........: Apple
    Name...........: Apple M2 Pro
`

// openCLWithCapabilities includes all capability fields found in OpenCL output.
const openCLWithCapabilities = `OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: NVIDIA Corporation
  Name....: NVIDIA CUDA
  Version.: OpenCL 3.0 CUDA 12.4.0

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 32
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce RTX 3090
    Version........: OpenCL 3.0
    Processor(s)...: 82
    Clock..........: 1695
    Memory.Total...: 24268 MB (limited to 6067 MB allocatable in one block)
    Memory.Free....: 23512 MB
    OpenCL.Version.: OpenCL C 3.0
    Driver.Version.: 535.129.03
`

// cudaWithCapabilities includes CUDA-specific capability fields.
const cudaWithCapabilities = `CUDA Info:
==========

  Backend Device ID #1
    Name...........: NVIDIA GeForce RTX 4090
    Processor(s)...: 128
    Clock..........: 2520
    Memory.Total...: 24564 MB
    Memory.Free....: 24100 MB
`

// metalWithCapabilities includes Metal-specific capability fields.
const metalWithCapabilities = `Metal Info:
===========

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 2
    Vendor.........: Apple
    Name...........: Apple M4
    Processor(s)...: 8
    Clock..........: N/A
    Memory.Total...: 10922 MB (limited to 4096 MB allocatable in one block)
    Memory.Free....: 5461 MB
`

// hipWithCapabilities includes HIP backend output.
//
//nolint:gosec // G101 - false positive, this is a test fixture not credentials
const hipWithCapabilities = `HIP Info:
=========

  Backend Device ID #1
    Name...........: AMD Radeon RX 5700 XT
    Processor(s)...: 20
    Clock..........: 2100
    Memory.Total...: 8176 MB
    Memory.Free....: 8176 MB
`

// nonExistentAbsPath returns a platform-appropriate absolute path that does
// not exist. On Windows, Unix-style paths like "/nonexistent" are not absolute
// (no drive letter), so we use a Windows-style path instead.
func nonExistentAbsPath() string {
	if runtime.GOOS == "windows" {
		return `C:\nonexistent\path\hashcat.exe`
	}

	return "/nonexistent/path/hashcat"
}

func TestEnumerateDevices_Scenario(t *testing.T) {
	tests := []struct {
		name        string
		hashcatPath string
		cmdFactory  CmdFactory
		wantErr     error
		wantAnyErr  bool // expect an error but no specific sentinel
		wantCount   int
		validate    func(t *testing.T, devices []Device)
	}{
		{
			name:        "SingleOpenCLGPU",
			hashcatPath: os.Args[0],
			cmdFactory:  helperCmdFactory(singleOpenCLGPU),
			wantCount:   1,
			validate: func(t *testing.T, devices []Device) {
				t.Helper()
				d := devices[0]
				require.Equal(t, 1, d.ID)
				require.Equal(t, "NVIDIA GeForce RTX 3090", d.Name)
				require.Equal(t, "GPU", d.Type)
				require.Equal(t, "OpenCL", d.Backend)
				require.Equal(t, "NVIDIA Corporation", d.Vendor)
				require.True(t, d.IsAvailable)
			},
		},
		{
			name:        "MultipleDevices",
			hashcatPath: os.Args[0],
			cmdFactory:  helperCmdFactory(multipleDevices),
			wantCount:   2,
			validate: func(t *testing.T, devices []Device) {
				t.Helper()
				require.Equal(t, "GPU", devices[0].Type)
				require.Equal(t, "OpenCL", devices[0].Backend)
				require.Equal(t, "CPU", devices[1].Type)
				require.Equal(t, "OpenCL", devices[1].Backend)
			},
		},
		{
			name:        "CUDADevice",
			hashcatPath: os.Args[0],
			cmdFactory:  helperCmdFactory(cudaDevice),
			wantCount:   1,
			validate: func(t *testing.T, devices []Device) {
				t.Helper()
				require.Equal(t, "CUDA", devices[0].Backend)
				require.Equal(t, "NVIDIA GeForce RTX 4090", devices[0].Name)
			},
		},
		{
			name:        "MetalDevice",
			hashcatPath: os.Args[0],
			cmdFactory:  helperCmdFactory(metalDevice),
			wantCount:   1,
			validate: func(t *testing.T, devices []Device) {
				t.Helper()
				require.Equal(t, "Metal", devices[0].Backend)
				require.Equal(t, "Apple M2 Pro", devices[0].Name)
				require.Equal(t, "Apple", devices[0].Vendor)
			},
		},
		{
			name:        "EmptyOutput",
			hashcatPath: os.Args[0],
			cmdFactory:  helperCmdFactory(""),
			wantErr:     ErrNoDevicesFound,
		},
		{
			name:        "InvalidBinaryPath",
			hashcatPath: "relative/path/hashcat",
			wantErr:     arch.ErrRelativePath,
		},
		{
			name:        "NonExistentBinary",
			hashcatPath: nonExistentAbsPath(),
			wantErr:     arch.ErrPathNotFound,
		},
		{
			name:        "ExecutionFailure",
			hashcatPath: os.Args[0],
			cmdFactory:  helperCmdFactoryExit(),
			wantAnyErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dm := &DeviceManager{cmdFactory: tc.cmdFactory}

			err := dm.EnumerateDevices(context.Background(), tc.hashcatPath)

			if tc.wantAnyErr {
				require.Error(t, err)

				return
			}

			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Len(t, dm.devices, tc.wantCount)

			if tc.validate != nil {
				tc.validate(t, dm.devices)
			}
		})
	}
}

func TestEnumerateDevices_ContextCancelled(t *testing.T) {
	dm := &DeviceManager{cmdFactory: helperCmdFactory(singleOpenCLGPU)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err := dm.EnumerateDevices(ctx, os.Args[0])
	require.Error(t, err)
}

func TestEnumerateDevices_EmptyPathFallbackFailure(t *testing.T) {
	// When hashcatPath is empty and FindHashcatBinary cannot find a binary,
	// EnumerateDevices should return an error wrapping ErrHashcatBinaryNotFound.

	// Save and restore agentstate paths that FindHashcatBinary checks.
	origHashcatPath := agentstate.State.HashcatPath
	origCrackersPath := agentstate.State.CrackersPath

	agentstate.State.HashcatPath = ""
	agentstate.State.CrackersPath = t.TempDir()

	t.Cleanup(func() {
		agentstate.State.HashcatPath = origHashcatPath
		agentstate.State.CrackersPath = origCrackersPath
	})

	// Clear system PATH so LookPath also fails.
	t.Setenv("PATH", t.TempDir())

	dm := &DeviceManager{}

	err := dm.EnumerateDevices(context.Background(), "")
	require.ErrorIs(t, err, cracker.ErrHashcatBinaryNotFound)
}

// --- Accessor tests (no subprocess needed) ---

func sampleDevices() []Device {
	return []Device{
		{ID: 1, Name: "RTX 3090", Type: "GPU", Backend: "OpenCL", Vendor: "NVIDIA", IsAvailable: true},
		{ID: 2, Name: "Core i9", Type: "CPU", Backend: "OpenCL", Vendor: "Intel", IsAvailable: true},
		{ID: 3, Name: "RTX 4090", Type: "GPU", Backend: "CUDA", Vendor: "NVIDIA", IsAvailable: true},
	}
}

func sampleDevicesWithUnavailable() []Device {
	return []Device{
		{ID: 1, Name: "RTX 3090", Type: "GPU", Backend: "OpenCL", Vendor: "NVIDIA", IsAvailable: true},
		{ID: 2, Name: "Core i9", Type: "CPU", Backend: "OpenCL", Vendor: "Intel", IsAvailable: false},
		{ID: 3, Name: "RTX 4090", Type: "GPU", Backend: "CUDA", Vendor: "NVIDIA", IsAvailable: true},
	}
}

func TestGetDevice_Found(t *testing.T) {
	dm := newTestManager(sampleDevices())

	d, found := dm.GetDevice(1)
	require.True(t, found)
	require.Equal(t, "RTX 3090", d.Name)
}

func TestGetDevice_NotFound(t *testing.T) {
	dm := newTestManager(sampleDevices())

	d, found := dm.GetDevice(99)
	require.False(t, found)
	require.Nil(t, d)
}

func TestGetDevicesByType_GPU(t *testing.T) {
	dm := newTestManager(sampleDevices())

	gpus := dm.GetDevicesByType("GPU")
	require.Len(t, gpus, 2)

	for _, d := range gpus {
		require.Equal(t, "GPU", d.Type)
	}
}

func TestGetDevicesByType_CPU(t *testing.T) {
	dm := newTestManager(sampleDevices())

	cpus := dm.GetDevicesByType("CPU")
	require.Len(t, cpus, 1)
	require.Equal(t, "Core i9", cpus[0].Name)
}

func TestGetDevicesByType_Empty(t *testing.T) {
	dm := newTestManager(sampleDevices())

	result := dm.GetDevicesByType("FPGA")
	require.NotNil(t, result)
	require.Empty(t, result)
}

func TestGetAllDevices_ReturnsCopy(t *testing.T) {
	dm := newTestManager(sampleDevices())

	all := dm.GetAllDevices()
	require.Len(t, all, 3)

	// Mutating the returned slice must not affect the manager.
	all[0].Name = "MUTATED"
	original, found := dm.GetDevice(1)
	require.True(t, found)
	require.Equal(t, "RTX 3090", original.Name)
}

func TestValidateDeviceIDs_AllValid(t *testing.T) {
	dm := newTestManager(sampleDevices())

	err := dm.ValidateDeviceIDs([]int{1, 2, 3})
	require.NoError(t, err)
}

func TestValidateDeviceIDs_OneInvalid(t *testing.T) {
	dm := newTestManager(sampleDevices())

	err := dm.ValidateDeviceIDs([]int{1, 99})
	require.ErrorIs(t, err, ErrInvalidDeviceID)
}

func TestValidateDeviceIDs_EmptySlice(t *testing.T) {
	dm := newTestManager(sampleDevices())

	err := dm.ValidateDeviceIDs([]int{})
	require.NoError(t, err)
}

// --- ValidateDeviceIDString tests ---

func TestValidateDeviceIDString(t *testing.T) {
	dm := newTestManager(sampleDevices())

	tests := []struct {
		name    string
		raw     string
		wantIDs []int
		wantErr error
	}{
		{
			name:    "EmptyString",
			raw:     "",
			wantIDs: nil,
			wantErr: nil,
		},
		{
			name:    "WhitespaceOnly",
			raw:     "   ",
			wantIDs: nil,
			wantErr: nil,
		},
		{
			name:    "SingleValidID",
			raw:     "1",
			wantIDs: []int{1},
			wantErr: nil,
		},
		{
			name:    "MultipleValidIDs",
			raw:     "1,2,3",
			wantIDs: []int{1, 2, 3},
			wantErr: nil,
		},
		{
			name:    "ValidIDsWithSpaces",
			raw:     " 1 , 2 , 3 ",
			wantIDs: []int{1, 2, 3},
			wantErr: nil,
		},
		{
			name:    "UnknownID",
			raw:     "1,99",
			wantIDs: nil,
			wantErr: ErrInvalidDeviceID,
		},
		{
			name:    "NonNumericToken",
			raw:     "1,abc,3",
			wantIDs: nil,
			wantErr: nil, // checked via require.Error below
		},
		{
			name:    "TrailingComma",
			raw:     "1,2,",
			wantIDs: []int{1, 2},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids, err := ValidateDeviceIDString(dm, tt.raw)

			if tt.name == "NonNumericToken" {
				require.Error(t, err)
				require.Contains(t, err.Error(), "non-numeric device ID")

				return
			}

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.wantIDs, ids)
		})
	}
}

func TestValidateDeviceIDString_NilManager(t *testing.T) {
	t.Parallel()

	_, err := ValidateDeviceIDString(nil, "1,2")
	require.Error(t, err)
	require.ErrorIs(t, err, ErrNoDevicesFound)
}

// --- Availability parsing tests ---

const skippedDeviceStatus = `OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: NVIDIA Corporation
  Name....: NVIDIA CUDA

  Backend Device ID #1
    Type...........: GPU
    Vendor.ID......: 32
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce RTX 3090
    Status.........: Active

  Backend Device ID #2
    Type...........: CPU
    Vendor.ID......: 64
    Vendor.........: Intel Corporation
    Name...........: Intel Core i9-12900K
    Status.........: Skipped
`

const skippedDeviceStandalone = `OpenCL Info:
============

OpenCL Platform ID #1
  Vendor..: NVIDIA Corporation
  Name....: NVIDIA CUDA

  Backend Device ID #1
    Type...........: GPU
    Vendor.........: NVIDIA Corporation
    Name...........: NVIDIA GeForce RTX 3090

  Backend Device ID #2
    Type...........: CPU
    Vendor.........: Intel Corporation
    Name...........: Intel Core i9-12900K
  * Device #2: Skipped
`

func TestParseDeviceOutput_SkippedStatus(t *testing.T) {
	dm := &DeviceManager{cmdFactory: helperCmdFactory(skippedDeviceStatus)}

	err := dm.EnumerateDevices(context.Background(), os.Args[0])
	require.NoError(t, err)
	require.Len(t, dm.devices, 2)

	require.True(t, dm.devices[0].IsAvailable, "Device #1 should be available")
	require.False(t, dm.devices[1].IsAvailable, "Device #2 should be unavailable (Skipped status)")
}

func TestParseDeviceOutput_SkippedStandalone(t *testing.T) {
	dm := &DeviceManager{cmdFactory: helperCmdFactory(skippedDeviceStandalone)}

	err := dm.EnumerateDevices(context.Background(), os.Args[0])
	require.NoError(t, err)
	require.Len(t, dm.devices, 2)

	require.True(t, dm.devices[0].IsAvailable, "Device #1 should be available")
	require.False(t, dm.devices[1].IsAvailable, "Device #2 should be unavailable (standalone Skipped)")
}

// --- ValidateDeviceIDsDetailed tests ---

func TestValidateDeviceIDsDetailed_AllValid(t *testing.T) {
	dm := newTestManager(sampleDevices())

	result := dm.ValidateDeviceIDsDetailed([]int{1, 3})
	require.Equal(t, []int{1, 3}, result.ValidIDs)
	require.Empty(t, result.UnknownIDs)
	require.Empty(t, result.UnavailableIDs)
}

func TestValidateDeviceIDsDetailed_MixedResults(t *testing.T) {
	dm := newTestManager(sampleDevicesWithUnavailable())

	result := dm.ValidateDeviceIDsDetailed([]int{1, 2, 3, 99})
	require.Equal(t, []int{1, 3}, result.ValidIDs)
	require.Equal(t, []int{99}, result.UnknownIDs)
	require.Equal(t, []int{2}, result.UnavailableIDs)
}

func TestValidateDeviceIDsDetailed_EmptySlice(t *testing.T) {
	dm := newTestManager(sampleDevices())

	result := dm.ValidateDeviceIDsDetailed([]int{})
	require.Empty(t, result.ValidIDs)
	require.Empty(t, result.UnknownIDs)
	require.Empty(t, result.UnavailableIDs)
}

// --- GetAvailableDeviceIDs tests ---

func TestGetAvailableDeviceIDs(t *testing.T) {
	dm := newTestManager(sampleDevicesWithUnavailable())

	ids := dm.GetAvailableDeviceIDs()
	require.Equal(t, []int{1, 3}, ids)
}

func TestGetAvailableDeviceIDs_AllAvailable(t *testing.T) {
	dm := newTestManager(sampleDevices())

	ids := dm.GetAvailableDeviceIDs()
	require.Equal(t, []int{1, 2, 3}, ids)
}

// --- HasDevices tests ---

func TestHasDevices_True(t *testing.T) {
	dm := newTestManager(sampleDevices())
	require.True(t, dm.HasDevices())
}

func TestHasDevices_False(t *testing.T) {
	dm := newTestManager([]Device{})
	require.False(t, dm.HasDevices())
}

// --- ValidateAndFilterDevices tests ---

func TestValidateAndFilterDevices_NilManager(t *testing.T) {
	result := ValidateAndFilterDevices(nil, "1,2", "1,2", noopWarn)
	require.Empty(t, result.BackendDeviceIDs)
	require.Equal(t, "1,2", result.OpenCLDeviceTypes)
}

func TestValidateAndFilterDevices_EmptyString(t *testing.T) {
	dm := newTestManager(sampleDevices())

	result := ValidateAndFilterDevices(dm, "", "3", noopWarn)
	require.Empty(t, result.BackendDeviceIDs)
	require.Equal(t, "3", result.OpenCLDeviceTypes)
}

func TestValidateAndFilterDevices_FiltersUnavailable(t *testing.T) {
	dm := newTestManager(sampleDevicesWithUnavailable())
	var warnings []string

	logFn := func(msg any, _ ...any) {
		warnings = append(warnings, fmt.Sprintf("%v", msg))
	}

	result := ValidateAndFilterDevices(dm, "1,2,3", "1", logFn)
	require.Equal(t, []int{1, 3}, result.BackendDeviceIDs)
	require.Equal(t, "1", result.OpenCLDeviceTypes)
	require.Len(t, warnings, 1, "should warn about unavailable device 2")
}

func TestValidateAndFilterDevices_FiltersUnknown(t *testing.T) {
	dm := newTestManager(sampleDevices())
	var warnings []string

	logFn := func(msg any, _ ...any) {
		warnings = append(warnings, fmt.Sprintf("%v", msg))
	}

	result := ValidateAndFilterDevices(dm, "1,99", "", logFn)
	require.Equal(t, []int{1}, result.BackendDeviceIDs)
	require.Len(t, warnings, 1, "should warn about unknown device 99")
}

func TestValidatedDevices_BackendDevicesFlag(t *testing.T) {
	vd := ValidatedDevices{BackendDeviceIDs: []int{1, 3, 5}}
	require.Equal(t, "1,3,5", vd.BackendDevicesFlag())

	empty := ValidatedDevices{}
	require.Empty(t, empty.BackendDevicesFlag())
}

func noopWarn(_ any, _ ...any) {}

// --- Capability parsing tests ---

func TestParseDeviceOutput_OpenCLCapabilities(t *testing.T) {
	t.Parallel()

	devs := parseDeviceOutput(openCLWithCapabilities)
	require.Len(t, devs, 1)

	d := devs[0]
	require.Equal(t, "82", d.Capabilities[CapProcessors])
	require.Equal(t, "1695", d.Capabilities[CapClock])
	require.Equal(t, "24268 MB (limited to 6067 MB allocatable in one block)", d.Capabilities[CapMemoryTotal])
	require.Equal(t, "23512 MB", d.Capabilities[CapMemoryFree])
	require.Equal(t, "OpenCL 3.0", d.Capabilities[CapVersion])
	require.Equal(t, "535.129.03", d.Capabilities[CapDriverVersion])
	require.Equal(t, "OpenCL C 3.0", d.Capabilities[CapOpenCLVersion])
}

func TestParseDeviceOutput_CUDACapabilities(t *testing.T) {
	t.Parallel()

	devs := parseDeviceOutput(cudaWithCapabilities)
	require.Len(t, devs, 1)

	d := devs[0]
	require.Equal(t, "CUDA", d.Backend)
	require.Equal(t, "128", d.Capabilities[CapProcessors])
	require.Equal(t, "2520", d.Capabilities[CapClock])
	require.Equal(t, "24564 MB", d.Capabilities[CapMemoryTotal])
	require.Equal(t, "24100 MB", d.Capabilities[CapMemoryFree])
	// CUDA has no Version, Driver.Version, or OpenCL.Version
	require.Empty(t, d.Capabilities[CapVersion])
	require.Empty(t, d.Capabilities[CapDriverVersion])
}

func TestParseDeviceOutput_MetalCapabilities(t *testing.T) {
	t.Parallel()

	devs := parseDeviceOutput(metalWithCapabilities)
	require.Len(t, devs, 1)

	d := devs[0]
	require.Equal(t, "Metal", d.Backend)
	require.Equal(t, "8", d.Capabilities[CapProcessors])
	require.Equal(t, "N/A", d.Capabilities[CapClock])
	require.Equal(t, "10922 MB (limited to 4096 MB allocatable in one block)", d.Capabilities[CapMemoryTotal])
	// Metal has no Driver.Version
	require.Empty(t, d.Capabilities[CapDriverVersion])
}

func TestParseDeviceOutput_HIPCapabilities(t *testing.T) {
	t.Parallel()

	devs := parseDeviceOutput(hipWithCapabilities)
	require.Len(t, devs, 1)

	d := devs[0]
	require.Equal(t, "HIP", d.Backend)
	require.Equal(t, "AMD Radeon RX 5700 XT", d.Name)
	require.Equal(t, "20", d.Capabilities[CapProcessors])
	require.Equal(t, "2100", d.Capabilities[CapClock])
	require.Equal(t, "8176 MB", d.Capabilities[CapMemoryTotal])
}

func TestParseDeviceOutput_CapabilitiesMapInitialized(t *testing.T) {
	t.Parallel()

	// Even the basic fixture without capability fields should have an initialized map.
	devs := parseDeviceOutput(singleOpenCLGPU)
	require.Len(t, devs, 1)
	require.NotNil(t, devs[0].Capabilities, "Capabilities map should be initialized, not nil")
}

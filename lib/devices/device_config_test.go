package devices

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDeviceConfig_NilDM(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("1,2", "1,2,3", nil)

	assert.False(t, dc.validated)
	assert.Nil(t, dc.DeviceManager())
	assert.Equal(t, "1,2", dc.RawBackendDevices())
	assert.Equal(t, "1,2,3", dc.RawOpenCLDevices())
	assert.Equal(t, []int{1, 2}, dc.enabledIDs)
}

func TestNewDeviceConfig_WithDM(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("1,2", "1", dm)

	assert.True(t, dc.validated)
	require.NotNil(t, dc.DeviceManager())
	assert.Equal(t, []int{1, 2}, dc.enabledIDs)
}

func TestNewDeviceConfig_EmptyStrings(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("", "", nil)

	assert.Empty(t, dc.enabledIDs)
	assert.Empty(t, dc.RawBackendDevices())
	assert.Empty(t, dc.RawOpenCLDevices())
}

func TestNewDeviceConfig_NonNumericBackend(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("OpenCL", "1", nil)

	// Non-numeric string fails parsing, enabledIDs stays empty.
	assert.Empty(t, dc.enabledIDs)
	// Raw string is preserved for fallback.
	assert.Equal(t, "OpenCL", dc.RawBackendDevices())
}

func TestResolvedBackendDevices_NilDM_ForwardsRaw(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("1,2", "", nil)
	assert.Equal(t, "1,2", dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_NilDM_ForwardsNonNumericRaw(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("OpenCL", "", nil)
	// Non-numeric raw string forwarded as-is when dm is nil.
	assert.Equal(t, "OpenCL", dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_NilDM_EmptyRaw(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("", "", nil)
	assert.Empty(t, dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_NilDM_TrimsWhitespace(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("  1,2  ", "", nil)
	assert.Equal(t, "1,2", dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_WithDM_ValidIDs(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("1,2", "", dm)

	assert.Equal(t, "1,2", dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_WithDM_SomeInvalid(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("1,99", "", dm)

	// ID 99 doesn't exist — only valid ID 1 returned.
	assert.Equal(t, "1", dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_WithDM_AllInvalid(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("98,99", "", dm)

	// All invalid — empty string (hashcat auto-detects).
	assert.Empty(t, dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_WithDM_EmptyRaw(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("", "", dm)

	// No IDs configured — empty (hashcat uses all).
	assert.Empty(t, dc.ResolvedBackendDevices())
}

func TestResolvedBackendDevices_WithDM_NonNumericRaw(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("OpenCL", "", dm)

	// Non-numeric raw, enabledIDs empty, validated=true → empty.
	assert.Empty(t, dc.ResolvedBackendDevices())
}

func TestResolvedOpenCLDevices_ReturnsRaw(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("", "1,2,3", nil)
	assert.Equal(t, "1,2,3", dc.ResolvedOpenCLDevices())
}

func TestResolvedOpenCLDevices_TrimsWhitespace(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("", "  1,2  ", nil)
	assert.Equal(t, "1,2", dc.ResolvedOpenCLDevices())
}

func TestResolvedOpenCLDevices_Empty(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("", "", nil)
	assert.Empty(t, dc.ResolvedOpenCLDevices())
}

func TestValidate_NilDM(t *testing.T) {
	t.Parallel()

	dc := NewDeviceConfig("1,2", "1", nil)

	var warnings []string
	logFn := func(msg any, _ ...any) {
		if s, ok := msg.(string); ok {
			warnings = append(warnings, s)
		}
	}

	result := dc.Validate(logFn)

	assert.Empty(t, result.BackendDeviceIDs)
	assert.Equal(t, "1", result.OpenCLDeviceTypes)
	assert.Empty(t, warnings)
}

func TestValidate_WithDM_ValidIDs(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("1,2,3", "1", dm)

	var warnings []string
	logFn := func(msg any, _ ...any) {
		if s, ok := msg.(string); ok {
			warnings = append(warnings, s)
		}
	}

	result := dc.Validate(logFn)

	assert.Equal(t, []int{1, 2, 3}, result.BackendDeviceIDs)
	assert.Equal(t, "1", result.OpenCLDeviceTypes)
	assert.Empty(t, warnings)
}

func TestValidate_WithDM_UnknownIDs(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("1,99", "1", dm)

	var warnings []string
	logFn := func(msg any, _ ...any) {
		if s, ok := msg.(string); ok {
			warnings = append(warnings, s)
		}
	}

	result := dc.Validate(logFn)

	assert.Equal(t, []int{1}, result.BackendDeviceIDs)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "not found")
}

func TestValidate_WithDM_EmptyIDs(t *testing.T) {
	t.Parallel()

	dm := newTestManager(sampleDevices())
	dc := NewDeviceConfig("", "1,2", dm)

	var warnings []string
	logFn := func(msg any, _ ...any) {
		if s, ok := msg.(string); ok {
			warnings = append(warnings, s)
		}
	}

	result := dc.Validate(logFn)

	assert.Empty(t, result.BackendDeviceIDs)
	assert.Equal(t, "1,2", result.OpenCLDeviceTypes)
	assert.Empty(t, warnings)
}

func TestIntsToCSV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ids  []int
		want string
	}{
		{name: "single", ids: []int{1}, want: "1"},
		{name: "multiple", ids: []int{1, 2, 3}, want: "1,2,3"},
		{name: "empty", ids: []int{}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, intsToCSV(tt.ids))
		})
	}
}

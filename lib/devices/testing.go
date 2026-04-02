package devices

// NewDeviceManagerForTest creates a DeviceManager pre-populated with the given
// devices. Intended for use by other packages' tests that need a non-nil
// DeviceManager without running hashcat.
func NewDeviceManagerForTest(devs []Device) *DeviceManager {
	copied := make([]Device, len(devs))
	copy(copied, devs)

	return &DeviceManager{devices: copied}
}

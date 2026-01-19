package hashcat

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatus_JSONSerialization(t *testing.T) {
	status := Status{
		OriginalLine: "test line",
		Time:         time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Session:      "test-session",
		Guess: statusGuess{
			GuessBase:        "/path/to/wordlist.txt",
			GuessBaseCount:   10000,
			GuessBaseOffset:  5000,
			GuessBasePercent: 50.0,
			GuessMod:         "",
			GuessModCount:    0,
			GuessModOffset:   0,
			GuessModPercent:  0.0,
			GuessMode:        0,
		},
		Status:          1,
		Target:          "target_hash",
		Progress:        []int64{5000, 10000},
		RestorePoint:    5000,
		RecoveredHashes: []int64{1, 10},
		RecoveredSalts:  []int64{0, 1},
		Rejected:        100,
		Devices: []StatusDevice{
			{
				DeviceID:   1,
				DeviceName: "NVIDIA GeForce RTX 3090",
				DeviceType: "GPU",
				Speed:      1000000000,
				Util:       99,
				Temp:       70,
			},
		},
		TimeStart:     1704110400,
		EstimatedStop: 1704114000,
	}

	// Test serialization
	data, err := json.Marshal(status)
	require.NoError(t, err)

	// Test deserialization
	var decoded Status
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, status.OriginalLine, decoded.OriginalLine)
	assert.Equal(t, status.Session, decoded.Session)
	assert.Equal(t, status.Status, decoded.Status)
	assert.Equal(t, status.Target, decoded.Target)
	assert.Equal(t, status.Progress, decoded.Progress)
	assert.Equal(t, status.RestorePoint, decoded.RestorePoint)
	assert.Equal(t, status.RecoveredHashes, decoded.RecoveredHashes)
	assert.Equal(t, status.RecoveredSalts, decoded.RecoveredSalts)
	assert.Equal(t, status.Rejected, decoded.Rejected)
	assert.Equal(t, status.TimeStart, decoded.TimeStart)
	assert.Equal(t, status.EstimatedStop, decoded.EstimatedStop)

	// Check guess
	assert.Equal(t, status.Guess.GuessBase, decoded.Guess.GuessBase)
	assert.Equal(t, status.Guess.GuessBaseCount, decoded.Guess.GuessBaseCount)
	assert.Equal(t, status.Guess.GuessBaseOffset, decoded.Guess.GuessBaseOffset)
	assert.InDelta(t, status.Guess.GuessBasePercent, decoded.Guess.GuessBasePercent, 0.001)

	// Check devices
	require.Len(t, decoded.Devices, 1)
	assert.Equal(t, status.Devices[0].DeviceID, decoded.Devices[0].DeviceID)
	assert.Equal(t, status.Devices[0].DeviceName, decoded.Devices[0].DeviceName)
	assert.Equal(t, status.Devices[0].DeviceType, decoded.Devices[0].DeviceType)
	assert.Equal(t, status.Devices[0].Speed, decoded.Devices[0].Speed)
	assert.Equal(t, status.Devices[0].Util, decoded.Devices[0].Util)
	assert.Equal(t, status.Devices[0].Temp, decoded.Devices[0].Temp)
}

func TestStatus_FromHashcatJSON(t *testing.T) {
	// Real hashcat JSON output format
	jsonData := `{
		"original_line": "",
		"time": "0001-01-01T00:00:00Z",
		"session": "attack-123",
		"guess": {
			"guess_base": "/wordlists/rockyou.txt",
			"guess_base_count": 14344392,
			"guess_base_offset": 7172196,
			"guess_base_percent": 50.0,
			"guess_mod": "",
			"guess_mod_count": 0,
			"guess_mod_offset": 0,
			"guess_mod_percent": 0.0,
			"guess_mode": 0
		},
		"status": 3,
		"target": "5f4dcc3b5aa765d61d8327deb882cf99",
		"progress": [7172196, 14344392],
		"restore_point": 7172196,
		"recovered_hashes": [0, 1],
		"recovered_salts": [0, 0],
		"rejected": 0,
		"devices": [
			{
				"device_id": 1,
				"device_name": "Intel Core i7",
				"device_type": "CPU",
				"speed": 123456789,
				"util": 95,
				"temp": 65
			}
		],
		"time_start": 1704110400,
		"estimated_stop": 1704114000
	}`

	var status Status
	err := json.Unmarshal([]byte(jsonData), &status)

	require.NoError(t, err)
	assert.Equal(t, "attack-123", status.Session)
	assert.Equal(t, int64(3), status.Status)
	assert.Equal(t, "5f4dcc3b5aa765d61d8327deb882cf99", status.Target)
	assert.Equal(t, []int64{7172196, 14344392}, status.Progress)
	assert.Equal(t, "/wordlists/rockyou.txt", status.Guess.GuessBase)
	assert.InDelta(t, 50.0, status.Guess.GuessBasePercent, 0.001)
	require.Len(t, status.Devices, 1)
	assert.Equal(t, "Intel Core i7", status.Devices[0].DeviceName)
}

func TestResult_JSONSerialization(t *testing.T) {
	result := Result{
		Timestamp: time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Hash:      "5f4dcc3b5aa765d61d8327deb882cf99",
		Plaintext: "password",
	}

	// Test serialization
	data, err := json.Marshal(result)
	require.NoError(t, err)

	// Test deserialization
	var decoded Result
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, result.Hash, decoded.Hash)
	assert.Equal(t, result.Plaintext, decoded.Plaintext)
	assert.True(t, result.Timestamp.Equal(decoded.Timestamp))
}

func TestStatusDevice_Fields(t *testing.T) {
	device := StatusDevice{
		DeviceID:   0,
		DeviceName: "AMD Radeon RX 6900 XT",
		DeviceType: "GPU",
		Speed:      5000000000,
		Util:       100,
		Temp:       85,
	}

	assert.Equal(t, int64(0), device.DeviceID)
	assert.Equal(t, "AMD Radeon RX 6900 XT", device.DeviceName)
	assert.Equal(t, "GPU", device.DeviceType)
	assert.Equal(t, int64(5000000000), device.Speed)
	assert.Equal(t, int64(100), device.Util)
	assert.Equal(t, int64(85), device.Temp)
}

func TestStatusGuess_Fields(t *testing.T) {
	guess := statusGuess{
		GuessBase:        "/wordlist.txt",
		GuessBaseCount:   1000000,
		GuessBaseOffset:  500000,
		GuessBasePercent: 50.0,
		GuessMod:         "/rules.rule",
		GuessModCount:    100,
		GuessModOffset:   50,
		GuessModPercent:  50.0,
		GuessMode:        0,
	}

	assert.Equal(t, "/wordlist.txt", guess.GuessBase)
	assert.Equal(t, int64(1000000), guess.GuessBaseCount)
	assert.Equal(t, int64(500000), guess.GuessBaseOffset)
	assert.InDelta(t, 50.0, guess.GuessBasePercent, 0.001)
	assert.Equal(t, "/rules.rule", guess.GuessMod)
	assert.Equal(t, int64(100), guess.GuessModCount)
	assert.Equal(t, int64(50), guess.GuessModOffset)
	assert.InDelta(t, 50.0, guess.GuessModPercent, 0.001)
	assert.Equal(t, int64(0), guess.GuessMode)
}

func TestAttackModeConstants(t *testing.T) {
	assert.Equal(t, int64(0), int64(attackModeDictionary))
	assert.Equal(t, int64(3), int64(AttackModeMask))
	assert.Equal(t, int64(6), int64(attackModeHybridDM))
	assert.Equal(t, int64(7), int64(attackModeHybridMD))
	assert.Equal(t, int64(9), int64(AttackBenchmark))
}

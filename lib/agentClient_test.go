package lib

import (
	"encoding/json"
	"testing"

	"github.com/unclesp1d3r/cipherswarmagent/lib/hashcat"
)

func TestConvertToTaskStatusGuessBasePercentage(t *testing.T) {
	data := `{
        "guess": {
            "guess_base": "base",
            "guess_base_count": 10,
            "guess_base_offset": 2,
            "guess_base_percent": 25.5,
            "guess_mod": "mod",
            "guess_mod_count": 20,
            "guess_mod_offset": 5,
            "guess_mod_percent": 30.7,
            "guess_mode": 0
        },
        "status": 1,
        "target": "target",
        "progress": [1,2],
        "restore_point": 0,
        "recovered_hashes": [0,0],
        "recovered_salts": [0,0],
        "rejected": 0,
        "time_start": 0,
        "estimated_stop": 0
    }`

	var update hashcat.Status
	if err := json.Unmarshal([]byte(data), &update); err != nil {
		t.Fatalf("failed to unmarshal status: %v", err)
	}

	devices := []hashcat.StatusDevice{{
		DeviceID:   1,
		DeviceName: "GPU0",
		DeviceType: "GPU",
		Speed:      100,
		Util:       50,
		Temp:       70,
	}}

	status := convertToTaskStatus(update, convertDeviceStatuses(devices))

	if status.HashcatGuess.GuessBasePercentage != update.Guess.GuessBasePercent {
		t.Fatalf("expected %v, got %v", update.Guess.GuessBasePercent, status.HashcatGuess.GuessBasePercentage)
	}
}

package hashcat

import (
	"time"
)

const (
	AttackModeDictionary = 0
	AttackModeCombinator = 1
	AttackModeMask       = 3
	AttackModeHybridDM   = 6
	AttackModeHybridMD   = 7
	AttackBenchmark      = 9
)

type HashcatStatusGuess struct {
	GuessBase        string  `json:"guess_base"`
	GuessBaseCount   uint64  `json:"guess_base_count"`
	GuessBaseOffset  uint64  `json:"guess_base_offset"`
	GuessBasePercent float32 `json:"guess_base_percent"`

	GuessMod        string  `json:"guess_mod"`
	GuessModCount   uint64  `json:"guess_mod_count"`
	GuessModOffset  uint64  `json:"guess_mod_offset"`
	GuessModPercent float32 `json:"guess_mod_percent"`

	GuessMode int `json:"guess_mode"`
}

type HashcatStatusDevice struct {
	DeviceID   int    `json:"device_id"`
	DeviceName string `json:"device_name"`
	DeviceType string `json:"device_type"`
	Speed      int    `json:"speed"`
	Util       int    `json:"util"`
	Temp       int    `json:"temp"`
}

type HashcatStatus struct {
	OriginalLine string    `json:"original_line"`
	Time         time.Time `json:"time"`

	Session         string                `json:"session"`
	Guess           HashcatStatusGuess    `json:"guess"`
	Status          int                   `json:"status"`
	Target          string                `json:"target"`
	Progress        []int                 `json:"progress"`
	RestorePoint    int                   `json:"restore_point"`
	RecoveredHashes []int                 `json:"recovered_hashes"`
	RecoveredSalts  []int                 `json:"recovered_salts"`
	Rejected        int                   `json:"rejected"`
	Devices         []HashcatStatusDevice `json:"devices"`

	TimeStart     int64 `json:"time_start"`
	EstimatedStop int64 `json:"estimated_stop"`
}

type HashcatResult struct {
	Timestamp time.Time `json:"timestamp"`
	Hash      string    `json:"hash"`
	Plaintext string    `json:"plaintext"`
}

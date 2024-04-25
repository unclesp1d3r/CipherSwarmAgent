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

	GuessMode int32 `json:"guess_mode"`
}

type HashcatStatusDevice struct {
	DeviceID   int32  `json:"device_id"`
	DeviceName string `json:"device_name"`
	DeviceType string `json:"device_type"`
	Speed      int64  `json:"speed"`
	Util       int32  `json:"util"`
	Temp       int32  `json:"temp"`
}

type HashcatStatus struct {
	OriginalLine string    `json:"original_line"`
	Time         time.Time `json:"time"`

	Session         string                `json:"session"`
	Guess           HashcatStatusGuess    `json:"guess"`
	Status          int32                 `json:"status"`
	Target          string                `json:"target"`
	Progress        []int64               `json:"progress"`
	RestorePoint    int64                 `json:"restore_point"`
	RecoveredHashes []int32               `json:"recovered_hashes"`
	RecoveredSalts  []int32               `json:"recovered_salts"`
	Rejected        int64                 `json:"rejected"`
	Devices         []HashcatStatusDevice `json:"devices"`

	TimeStart     int64 `json:"time_start"`
	EstimatedStop int64 `json:"estimated_stop"`
}

type HashcatResult struct {
	Timestamp time.Time `json:"timestamp"`
	Hash      string    `json:"hash"`
	Plaintext string    `json:"plaintext"`
}

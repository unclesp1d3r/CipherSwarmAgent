package hashcat

import (
	"time"
)

const (
	AttackModeDictionary = 0 // AttackModeDictionary is the attack mode for dictionary attacks
	AttackModeCombinator = 1 // AttackModeCombinator is the attack mode for combinator attacks
	AttackModeMask       = 3 // AttackModeMask is the attack mode for mask attacks
	AttackModeHybridDM   = 6 // AttackModeHybridDM is the attack mode for hybrid dictionary + mask attacks
	AttackModeHybridMD   = 7 // AttackModeHybridMD is the attack mode for hybrid mask + dictionary attacks
	AttackBenchmark      = 9 // AttackBenchmark is the attack mode for benchmarking
)

type StatusGuess struct {
	GuessBase        string  `json:"guess_base"`         // The base wordlist used for the attack
	GuessBaseCount   uint64  `json:"guess_base_count"`   // The number of words in the base wordlist
	GuessBaseOffset  uint64  `json:"guess_base_offset"`  // The offset into the base wordlist
	GuessBasePercent float32 `json:"guess_base_percent"` // The percentage of the base wordlist that has been processed

	GuessMod        string  `json:"guess_mod"`         // The modifier wordlist used for the attack
	GuessModCount   uint64  `json:"guess_mod_count"`   // The number of words in the modifier wordlist
	GuessModOffset  uint64  `json:"guess_mod_offset"`  // The offset into the modifier wordlist
	GuessModPercent float32 `json:"guess_mod_percent"` // The percentage of the modifier wordlist that has been processed

	GuessMode int32 `json:"guess_mode"` // The attack mode
}

type StatusDevice struct {
	DeviceID   int32  `json:"device_id"`   // The device ID
	DeviceName string `json:"device_name"` // The device name
	DeviceType string `json:"device_type"` // The device type
	Speed      int64  `json:"speed"`       // The speed of the device
	Util       int32  `json:"util"`        // The utilization of the device
	Temp       int32  `json:"temp"`        // The temperature of the device
}

type Status struct {
	OriginalLine string    `json:"original_line"` // The original line from hashcat
	Time         time.Time `json:"time"`          // The time the status was received

	Session         string         `json:"session"`          // The session ID
	Guess           StatusGuess    `json:"guess"`            // The current guess
	Status          int32          `json:"status"`           // The status of the attack
	Target          string         `json:"target"`           // The target hash
	Progress        []int64        `json:"progress"`         // The progress of the attack
	RestorePoint    int64          `json:"restore_point"`    // The restore point
	RecoveredHashes []int32        `json:"recovered_hashes"` // The number of recovered hashes
	RecoveredSalts  []int32        `json:"recovered_salts"`  // The number of recovered salts
	Rejected        int64          `json:"rejected"`         // The number of rejected hashes
	Devices         []StatusDevice `json:"devices"`          // The devices used for the attack

	TimeStart     int64 `json:"time_start"`     // The start time of the attack
	EstimatedStop int64 `json:"estimated_stop"` // The estimated stop time of the attack
}

type Result struct {
	Timestamp time.Time `json:"timestamp"` // The time the result was received
	Hash      string    `json:"hash"`      // The hash
	Plaintext string    `json:"plaintext"` // The plaintext
}

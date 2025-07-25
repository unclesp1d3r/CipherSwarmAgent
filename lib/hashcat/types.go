package hashcat

import (
	"time"
)

// Attack mode constants define the different types of hashcat attacks.
const (
	attackModeDictionary = 0 // attackModeDictionary is the attack mode for dictionary attacks
	// AttackModeMask is the attack mode for mask attacks.
	AttackModeMask     = 3
	attackModeHybridDM = 6 // attackModeHybridDM is the attack mode for hybrid dictionary + mask attacks
	attackModeHybridMD = 7 // attackModeHybridMD is the attack mode for hybrid mask + dictionary attacks
	AttackBenchmark    = 9 // AttackBenchmark is the attack mode for benchmarking
)

// statusGuess represents the state and statistics of the current guess in a password cracking attack.
// It holds information regarding the base and modifier wordlists used, including their counts, offsets, and processing percentages.
// It also encapsulates the attack mode being used.
type statusGuess struct {
	GuessBase        string  `json:"guess_base"`         // The base wordlist used for the attack
	GuessBaseCount   int64   `json:"guess_base_count"`   // The number of words in the base wordlist
	GuessBaseOffset  int64   `json:"guess_base_offset"`  // The offset into the base wordlist
	GuessBasePercent float64 `json:"guess_base_percent"` // The percentage of the base wordlist that has been processed
	GuessMod         string  `json:"guess_mod"`          // The modifier wordlist used for the attack
	GuessModCount    int64   `json:"guess_mod_count"`    // The number of words in the modifier wordlist
	GuessModOffset   int64   `json:"guess_mod_offset"`   // The offset into the modifier wordlist
	GuessModPercent  float64 `json:"guess_mod_percent"`  // The percentage of the modifier wordlist that has been processed
	GuessMode        int64   `json:"guess_mode"`         // The attack mode
}

// StatusDevice represents the state and statistics of a device involved in an operation.
// It contains information such as the device ID, name, type, speed, utilization, and temperature.
type StatusDevice struct {
	DeviceID   int64  `json:"device_id"`   // The device ID
	DeviceName string `json:"device_name"` // The device name
	DeviceType string `json:"device_type"` // The device type
	Speed      int64  `json:"speed"`       // The speed of the device
	Util       int64  `json:"util"`        // The utilization of the device
	Temp       int64  `json:"temp"`        // The temperature of the device
}

// Status represents the current status of a hashcat operation.
type Status struct {
	OriginalLine    string         `json:"original_line"`    // The original line from hashcat
	Time            time.Time      `json:"time"`             // The time the status was received
	Session         string         `json:"session"`          // The session ID
	Guess           statusGuess    `json:"guess"`            // The current guess
	Status          int64          `json:"status"`           // The status of the attack
	Target          string         `json:"target"`           // The target hash
	Progress        []int64        `json:"progress"`         // The progress of the attack
	RestorePoint    int64          `json:"restore_point"`    // The restore point
	RecoveredHashes []int64        `json:"recovered_hashes"` // The number of recovered hashes
	RecoveredSalts  []int64        `json:"recovered_salts"`  // The number of recovered salts
	Rejected        int64          `json:"rejected"`         // The number of rejected hashes
	Devices         []StatusDevice `json:"devices"`          // The devices used for the attack
	TimeStart       int64          `json:"time_start"`       // The start time of the attack
	EstimatedStop   int64          `json:"estimated_stop"`   // The estimated stop time of the attack
}

// Result represents the outcome of a hashcat operation, including the timestamp, hash, and plaintext result.
type Result struct {
	Timestamp time.Time `json:"timestamp"` // The time the result was received
	Hash      string    `json:"hash"`      // The hash
	Plaintext string    `json:"plaintext"` // The plaintext
}

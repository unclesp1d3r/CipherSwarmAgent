// Package hashcat provides types and constants for hashcat session management.
// It defines the data structures used to communicate with hashcat processes and
// track the status of hash cracking operations.
package hashcat

import (
	"time"
)

// Attack mode constants define the different types of hashcat attacks.
const (
	attackModeDictionary = 0 // Dictionary attack mode
	// AttackModeMask is the attack mode for mask attacks.
	AttackModeMask     = 3
	attackModeHybridDM = 6 // Hybrid dictionary + mask attack mode
	attackModeHybridMD = 7 // Hybrid mask + dictionary attack mode
	// AttackBenchmark is the attack mode for benchmarking.
	AttackBenchmark = 9
)

// statusGuess represents the state and statistics of the current guess in a password cracking attack.
// It holds information about the base and modifier wordlists being used, including progress tracking
// and the attack mode being employed.
type statusGuess struct {
	GuessBase        string  `json:"guess_base"`         // Base wordlist path
	GuessBaseCount   int64   `json:"guess_base_count"`   // Total words in base wordlist
	GuessBaseOffset  int64   `json:"guess_base_offset"`  // Current position in base wordlist
	GuessBasePercent float64 `json:"guess_base_percent"` // Percentage of base wordlist processed
	GuessMod         string  `json:"guess_mod"`          // Modifier wordlist path
	GuessModCount    int64   `json:"guess_mod_count"`    // Total words in modifier wordlist
	GuessModOffset   int64   `json:"guess_mod_offset"`   // Current position in modifier wordlist
	GuessModPercent  float64 `json:"guess_mod_percent"`  // Percentage of modifier wordlist processed
	GuessMode        int64   `json:"guess_mode"`         // Active attack mode
}

// StatusDevice represents a computing device (GPU/CPU) involved in a hash cracking operation.
// It tracks device identification, performance metrics, and operational status.
type StatusDevice struct {
	DeviceID   int64  `json:"device_id"`   // Unique device identifier
	DeviceName string `json:"device_name"` // Human-readable device name
	DeviceType string `json:"device_type"` // Device type (e.g., "GPU", "CPU")
	Speed      int64  `json:"speed"`       // Current processing speed (hashes/second)
	Util       int64  `json:"util"`        // Device utilization percentage (0-100)
	Temp       int64  `json:"temp"`        // Device temperature in Celsius
}

// Status represents the current operational status of a hashcat process.
// It contains comprehensive information about the attack progress, performance,
// and estimated completion time.
type Status struct {
	OriginalLine    string         `json:"original_line"`    // Raw status line from hashcat
	Time            time.Time      `json:"time"`             // Timestamp when status was captured
	Session         string         `json:"session"`          // Unique session identifier
	Guess           statusGuess    `json:"guess"`            // Current guess/wordlist state
	Status          int64          `json:"status"`           // Hashcat status code
	Target          string         `json:"target"`           // Target hash or hash list
	Progress        []int64        `json:"progress"`         // Current and total progress values
	RestorePoint    int64          `json:"restore_point"`    // Position for session restoration
	RecoveredHashes []int64        `json:"recovered_hashes"` // Count of cracked hashes
	RecoveredSalts  []int64        `json:"recovered_salts"`  // Count of recovered salts
	Rejected        int64          `json:"rejected"`         // Number of rejected candidates
	Devices         []StatusDevice `json:"devices"`          // Active compute devices
	TimeStart       int64          `json:"time_start"`       // Attack start timestamp (Unix)
	EstimatedStop   int64          `json:"estimated_stop"`   // Estimated completion timestamp (Unix)
}

// Result represents a successfully cracked hash.
// It contains the timestamp, original hash, and recovered plaintext.
type Result struct {
	Timestamp time.Time `json:"timestamp"` // When the hash was cracked
	Hash      string    `json:"hash"`      // Original hash value
	Plaintext string    `json:"plaintext"` // Recovered plaintext password
}

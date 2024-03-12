package hashcat

// Arguments for hashcat
type Args struct {
	// Session represents the session identifier for the hashcatArgs.
	// It is a pointer to a string that holds the session value.
	Session *string

	AttackMode *AttackMode `json:"attackMode"`
	HashMode   *HashMode   `json:"hashMode"`

	// Dictionaries represents a list of file paths to dictionaries.
	// These dictionaries are used as input for the hashcat algorithm.
	// Each dictionary file contains a list of words that can be used for password cracking.
	// The dictionaries are specified as file paths.
	Dictionaries *[]string `json:"dictionaries"`
	// Rules is a pointer to a slice of strings that represents the files containing hashcat rules.
	// These rules are used for password cracking and can be customized to apply specific transformations to passwords.
	// The rules are specified as file paths.
	Rules *[]string `json:"rules"`
	// Mask represents the direct input for the hashcat mask. It specifies the pattern or mask to be used for generating password candidates during the cracking process.
	Mask *string `json:"mask"`
	// MaskFile represents the path to a file containing a mask for hashcat.
	// This field is used as an input parameter for hashcatArgs.
	MaskFile *string `json:"maskFile"`
	// LeftDictionary represents the path to the left dictionary file.
	// It is used as an input for the hashcatArgs.
	LeftDictionary *string `json:"leftDictionary"`
	// LeftRule represents the left rule for the hashcatArgs.
	// It is used as a direct input.
	LeftRule *string `json:"leftRule"`
	// RightDictionary represents the path to the dictionary file used for the right side of the comparison.
	// It is a JSON field and should be specified as a file path.
	RightDictionary *string `json:"rightDictionary"`
	// RightRule represents the right rule for the hashcatArgs.
	// It is a pointer to a string and is used for direct input.
	RightRule *string `json:"rightRule"`

	CustomCharset1 *string `json:"customCharset1"`
	CustomCharset2 *string `json:"customCharset2"`
	CustomCharset3 *string `json:"customCharset3"`
	CustomCharset4 *string `json:"customCharset4"`

	// EnableMaskIncrementMode is a JSON tag for enabling the mask increment mode.
	EnableMaskIncrementMode *bool  `json:"enableMaskIncrementMode"`
	MaskIncrementMin        *int64 `json:"maskIncrementMin"`
	MaskIncrementMax        *int64 `json:"maskIncrementMax"`

	Hash *string `json:"hash"` // File

	Quiet                           *bool `json:"quiet"`
	DisablePotFile                  *bool `json:"disablePotFile"`
	DisableLogFile                  *bool `json:"disableLogFile"`
	EnableOptimizedKernel           *bool `json:"enableOptimizedKernel"`
	EnableSlowerCandidateGenerators *bool `json:"enableSlowerCandidateGenerators"`
	RemoveFoundHashes               *bool `json:"removeFoundHashes"`
	IgnoreUsernames                 *bool `json:"ignoreUsernames"`
	DisableSelfTest                 *bool `json:"disableSelfTest"`
	IgnoreWarnings                  *bool `json:"ignoreWarnings"`

	DevicesIDs      *[]int64 `json:"devicesIDs"`
	DevicesTypes    *[]int64 `json:"devicesTypes"`
	WorkloadProfile *int64   `json:"workloadProfile"`

	DisableMonitor *bool  `json:"disableMonitor"`
	TempAbort      *int64 `json:"tempAbort"`

	MarkovDisable   *bool  `json:"markovDisable"`
	MarkovClassic   *bool  `json:"markovClassic"`
	MarkovThreshold *int64 `json:"markovThreshold"`

	ExtraArguments *[]string `json:"extraArguments"`

	StatusTimer *int64 `json:"statusTimer"`

	OutputFile   *string  `json:"outputFile"`
	OutputFormat *[]int64 `json:"outputFormat"`
}

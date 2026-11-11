// utils.go
package cipherSwarmAgent

type Utils struct{}

func NewUtils() *Utils {
	return &Utils{}
}

func (u *Utils) ReadConfigFile(filename string) ([]byte, error) {
	// Read config file logic
	return nil, nil
}

func (u *Utils) WriteConfigFile(filename string, data []byte) error {
	// Write config file logic
	return nil
}
// display.go
package cipherSwarmAgent

type Display struct{}

func NewDisplay() *Display {
	return &Display{}
}

func (d *Display) DisplayStartup() string {
	return "Startup message"
}

func (d *Display) DisplayAuthenticated() string {
	return "Authentication successful"
}

func (d *Display) DisplayNewTask() string {
	return "New task notification"
}

func (d *Display) DisplayNewAttack() string {
	return "New attack notification"
}

func (d *Display) DisplayInactive() string {
	return "Inactive state"
}

func (d *Display) DisplayShuttingDown() string {
	return "Shutdown process"
}
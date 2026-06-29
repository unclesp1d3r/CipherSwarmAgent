// Package util provides small generic helpers shared across the agent.
package util

// UnwrapOr returns the dereferenced pointer value, or the given default if the pointer is nil.
func UnwrapOr[T any](ptr *T, defaultVal T) T {
	if ptr != nil {
		return *ptr
	}

	return defaultVal
}

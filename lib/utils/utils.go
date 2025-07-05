package utils

import (
	"fmt"
)

// calculatePercentage calculates the percentage of a given value relative to a total, formatted to two decimal places.
// It returns "0.00%" if the total is zero to prevent division by zero errors.
func CalculatePercentage(value, total float64) string {
	if total == 0 {
		return "0.00%"
	}
	percentage := (value / total) * 100
	return fmt.Sprintf("%.2f%%", percentage)
}

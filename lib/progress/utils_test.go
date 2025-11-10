package progress

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCalculatePercentage tests the CalculatePercentage function.
func TestCalculatePercentage(t *testing.T) {
	tests := []struct {
		name     string
		value    float64
		total    float64
		expected string
	}{
		{
			name:     "50% progress",
			value:    50,
			total:    100,
			expected: "50.00%",
		},
		{
			name:     "25% progress",
			value:    25,
			total:    100,
			expected: "25.00%",
		},
		{
			name:     "0% progress",
			value:    0,
			total:    100,
			expected: "0.00%",
		},
		{
			name:     "100% progress",
			value:    100,
			total:    100,
			expected: "100.00%",
		},
		{
			name:     "division by zero - returns 0.00%",
			value:    50,
			total:    0,
			expected: "0.00%",
		},
		{
			name:     "fractional percentage",
			value:    33.33,
			total:    100,
			expected: "33.33%",
		},
		{
			name:     "value greater than total",
			value:    150,
			total:    100,
			expected: "150.00%",
		},
		{
			name:     "very small values",
			value:    0.01,
			total:    1,
			expected: "1.00%",
		},
		{
			name:     "large numbers",
			value:    1000000,
			total:    10000000,
			expected: "10.00%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculatePercentage(tt.value, tt.total)
			assert.Equal(t, tt.expected, result)
		})
	}
}

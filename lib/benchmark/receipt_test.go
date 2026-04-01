package benchmark

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unclesp1d3r/cipherswarmagent/lib/api"
	"github.com/unclesp1d3r/cipherswarmagent/lib/testhelpers"
)

func TestValidateReceipt(t *testing.T) {
	t.Cleanup(testhelpers.SetupMinimalTestState(1))

	msg := "some entries invalid"
	okMsg := "all good"

	tests := []struct {
		name        string
		sentCount   int
		receipt     api.BenchmarkReceipt
		expectError bool
	}{
		{
			name:      "all processed",
			sentCount: 10,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  10,
				ProcessedCount: 10,
				FailedCount:    0,
			},
			expectError: false,
		},
		{
			name:      "partial failures",
			sentCount: 10,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  10,
				ProcessedCount: 8,
				FailedCount:    2,
				Message:        &msg,
			},
			expectError: false,
		},
		{
			name:      "count mismatch warns but succeeds",
			sentCount: 10,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  8,
				ProcessedCount: 8,
				FailedCount:    0,
			},
			expectError: false,
		},
		{
			name:      "zero received returns error",
			sentCount: 10,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  0,
				ProcessedCount: 0,
				FailedCount:    0,
			},
			expectError: true,
		},
		{
			name:      "all failed returns error",
			sentCount: 5,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  5,
				ProcessedCount: 0,
				FailedCount:    5,
				Message:        &msg,
			},
			expectError: true,
		},
		{
			name:      "zero sent zero received succeeds",
			sentCount: 0,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  0,
				ProcessedCount: 0,
				FailedCount:    0,
			},
			expectError: false,
		},
		{
			name:      "message only no failures",
			sentCount: 3,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  3,
				ProcessedCount: 3,
				FailedCount:    0,
				Message:        &okMsg,
			},
			expectError: false,
		},
		{
			name:      "negative received count",
			sentCount: 5,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  -1,
				ProcessedCount: 0,
				FailedCount:    0,
			},
			expectError: true,
		},
		{
			name:      "negative failed count",
			sentCount: 5,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  5,
				ProcessedCount: 5,
				FailedCount:    -1,
			},
			expectError: true,
		},
		{
			name:      "negative processed count",
			sentCount: 5,
			receipt: api.BenchmarkReceipt{
				ReceivedCount:  5,
				ProcessedCount: -1,
				FailedCount:    0,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReceipt(tt.sentCount, &tt.receipt)
			if tt.expectError {
				require.Error(t, err)
				assert.ErrorIs(t, err, errBadResponse)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

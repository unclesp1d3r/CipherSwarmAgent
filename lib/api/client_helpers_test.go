package api

import (
	"io"
	"math"
	"math/bits"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// newAPIError tests
// ---------------------------------------------------------------------------

func TestNewAPIError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		status     string
		body       []byte
		wantCode   int
		wantMsg    string
		wantBody   string
	}{
		{
			name:       "404 not found",
			statusCode: http.StatusNotFound,
			status:     "404 Not Found",
			body:       []byte(`{"error":"resource not found"}`),
			wantCode:   http.StatusNotFound,
			wantMsg:    "404 Not Found",
			wantBody:   `{"error":"resource not found"}`,
		},
		{
			name:       "500 with empty body",
			statusCode: http.StatusInternalServerError,
			status:     "500 Internal Server Error",
			body:       []byte{},
			wantCode:   http.StatusInternalServerError,
			wantMsg:    "500 Internal Server Error",
			wantBody:   "",
		},
		{
			name:       "nil body",
			statusCode: http.StatusBadGateway,
			status:     "502 Bad Gateway",
			body:       nil,
			wantCode:   http.StatusBadGateway,
			wantMsg:    "502 Bad Gateway",
			wantBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := newAPIError(tt.statusCode, tt.status, tt.body)

			assert.Equal(t, tt.wantCode, err.StatusCode)
			assert.Equal(t, tt.wantMsg, err.Message)
			assert.Equal(t, tt.wantBody, err.Body)
		})
	}
}

// ---------------------------------------------------------------------------
// ResponseStream tests
// ---------------------------------------------------------------------------

func TestResponseStream(t *testing.T) {
	t.Parallel()

	t.Run("nil response returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, ResponseStream(nil))
	})

	t.Run("empty body returns nil", func(t *testing.T) {
		t.Parallel()
		resp := &GetTaskZapsResponse{Body: []byte{}}
		assert.Nil(t, ResponseStream(resp))
	})

	t.Run("populated body returns readable stream", func(t *testing.T) {
		t.Parallel()
		content := []byte("hash1:plain1\nhash2:plain2\n")
		resp := &GetTaskZapsResponse{Body: content}

		stream := ResponseStream(resp)
		require.NotNil(t, stream)

		data, err := io.ReadAll(stream)
		require.NoError(t, err)
		assert.Equal(t, content, data)

		require.NoError(t, stream.Close())
	})
}

// ---------------------------------------------------------------------------
// HashListResponseStream tests
// ---------------------------------------------------------------------------

func TestHashListResponseStream(t *testing.T) {
	t.Parallel()

	t.Run("nil response returns nil", func(t *testing.T) {
		t.Parallel()
		assert.Nil(t, HashListResponseStream(nil))
	})

	t.Run("empty body returns nil", func(t *testing.T) {
		t.Parallel()
		resp := &GetHashListResponse{Body: []byte{}}
		assert.Nil(t, HashListResponseStream(resp))
	})

	t.Run("populated body returns readable reader", func(t *testing.T) {
		t.Parallel()
		content := []byte("d41d8cd98f00b204e9800998ecf8427e\n5d41402abc4b2a76b9719d911017c592\n")
		resp := &GetHashListResponse{Body: content}

		reader := HashListResponseStream(resp)
		require.NotNil(t, reader)

		data, err := io.ReadAll(reader)
		require.NoError(t, err)
		assert.Equal(t, content, data)
	})
}

// ---------------------------------------------------------------------------
// ConvertInt64SliceToInt tests
// ---------------------------------------------------------------------------

func TestConvertInt64SliceToInt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       []int64
		wantResult  []int
		wantClamped int
	}{
		{
			name:        "nil slice",
			input:       nil,
			wantResult:  []int{},
			wantClamped: 0,
		},
		{
			name:        "empty slice",
			input:       []int64{},
			wantResult:  []int{},
			wantClamped: 0,
		},
		{
			name:        "valid values",
			input:       []int64{1, 2, 3, 100, -50},
			wantResult:  []int{1, 2, 3, 100, -50},
			wantClamped: 0,
		},
		{
			name:        "single zero",
			input:       []int64{0},
			wantResult:  []int{0},
			wantClamped: 0,
		},
		{
			name:        "max int boundary",
			input:       []int64{int64(math.MaxInt)},
			wantResult:  []int{math.MaxInt},
			wantClamped: 0,
		},
		{
			name:        "min int boundary",
			input:       []int64{int64(math.MinInt)},
			wantResult:  []int{math.MinInt},
			wantClamped: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, clamped := ConvertInt64SliceToInt(tt.input)
			assert.Equal(t, tt.wantResult, result)
			assert.Equal(t, tt.wantClamped, clamped)
		})
	}
}

// TestConvertInt64SliceToInt_Overflow verifies the clamping behavior for values
// that exceed the platform's int range. On 64-bit platforms (where int == int64),
// no int64 value can overflow, so the clamping path is unreachable and this test
// verifies that MaxInt64/MinInt64 pass through without clamping.
// On 32-bit platforms, values beyond MaxInt32/MinInt32 are clamped to zero.
func TestConvertInt64SliceToInt_Overflow(t *testing.T) {
	t.Parallel()

	is64bit := bits.UintSize == 64

	if is64bit {
		// On 64-bit: int can hold all int64 values, no clamping occurs.
		result, clamped := ConvertInt64SliceToInt([]int64{math.MaxInt64, math.MinInt64})
		assert.Equal(t, []int{math.MaxInt64, math.MinInt64}, result)
		assert.Equal(t, 0, clamped)
	} else {
		// On 32-bit: values beyond MaxInt32/MinInt32 are clamped to zero.
		t.Run("overflow clamps to zero", func(t *testing.T) {
			t.Parallel()
			result, clamped := ConvertInt64SliceToInt([]int64{math.MaxInt64})
			assert.Equal(t, []int{0}, result)
			assert.Equal(t, 1, clamped)
		})

		t.Run("underflow clamps to zero", func(t *testing.T) {
			t.Parallel()
			result, clamped := ConvertInt64SliceToInt([]int64{math.MinInt64})
			assert.Equal(t, []int{0}, result)
			assert.Equal(t, 1, clamped)
		})

		t.Run("mixed valid and overflow", func(t *testing.T) {
			t.Parallel()
			result, clamped := ConvertInt64SliceToInt([]int64{42, math.MaxInt64, -7, math.MinInt64, 99})
			assert.Equal(t, []int{42, 0, -7, 0, 99}, result)
			assert.Equal(t, 2, clamped)
		})
	}
}

package api

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ErrorObject tests
// ---------------------------------------------------------------------------

func TestErrorObject_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      ErrorObject
		expected string
	}{
		{
			name:     "returns error message",
			err:      ErrorObject{Err: "something went wrong"},
			expected: "something went wrong",
		},
		{
			name:     "empty error message",
			err:      ErrorObject{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestErrorObject_Get(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		obj       ErrorObject
		field     string
		wantVal   any
		wantFound bool
	}{
		{
			name:      "nil map returns nil false",
			obj:       ErrorObject{},
			field:     "foo",
			wantVal:   nil,
			wantFound: false,
		},
		{
			name: "existing key returns value",
			obj: ErrorObject{
				AdditionalProperties: map[string]any{"code": 42},
			},
			field:     "code",
			wantVal:   42,
			wantFound: true,
		},
		{
			name: "missing key returns nil false",
			obj: ErrorObject{
				AdditionalProperties: map[string]any{"code": 42},
			},
			field:     "missing",
			wantVal:   nil,
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			val, found := tt.obj.Get(tt.field)
			assert.Equal(t, tt.wantVal, val)
			assert.Equal(t, tt.wantFound, found)
		})
	}
}

func TestErrorObject_Set(t *testing.T) {
	t.Parallel()

	t.Run("initializes nil map", func(t *testing.T) {
		t.Parallel()
		obj := &ErrorObject{}
		obj.Set("key", "value")
		val, found := obj.Get("key")
		assert.True(t, found)
		assert.Equal(t, "value", val)
	})

	t.Run("adds to existing map", func(t *testing.T) {
		t.Parallel()
		obj := &ErrorObject{
			AdditionalProperties: map[string]any{"existing": 1},
		}
		obj.Set("new", 2)
		val, found := obj.Get("new")
		assert.True(t, found)
		assert.Equal(t, 2, val)
		// Existing key still present
		val, found = obj.Get("existing")
		assert.True(t, found)
		assert.Equal(t, 1, val)
	})
}

func TestErrorObject_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		wantErr        bool
		wantErrMsg     string
		wantAdditional map[string]any
	}{
		{
			name:       "error field only",
			input:      `{"error":"bad request"}`,
			wantErr:    false,
			wantErrMsg: "bad request",
		},
		{
			name:       "error with additional properties",
			input:      `{"error":"validation failed","code":422,"field":"email"}`,
			wantErr:    false,
			wantErrMsg: "validation failed",
			wantAdditional: map[string]any{
				"code":  float64(422), // JSON numbers unmarshal as float64
				"field": "email",
			},
		},
		{
			name:       "no error field",
			input:      `{"code":500}`,
			wantErr:    false,
			wantErrMsg: "",
			wantAdditional: map[string]any{
				"code": float64(500),
			},
		},
		{
			name:    "invalid JSON",
			input:   `{not valid`,
			wantErr: true,
		},
		{
			name:    "error field is not a string",
			input:   `{"error":123}`,
			wantErr: true,
		},
		{
			name:       "empty object",
			input:      `{}`,
			wantErr:    false,
			wantErrMsg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var obj ErrorObject
			err := json.Unmarshal([]byte(tt.input), &obj)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantErrMsg, obj.Err)
			if tt.wantAdditional != nil {
				for k, v := range tt.wantAdditional {
					got, found := obj.Get(k)
					assert.True(t, found, "expected additional property %q", k)
					assert.Equal(t, v, got, "additional property %q mismatch", k)
				}
			}
		})
	}
}

func TestErrorObject_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		obj  ErrorObject
		want map[string]any
	}{
		{
			name: "error field only",
			obj:  ErrorObject{Err: "not found"},
			want: map[string]any{"error": "not found"},
		},
		{
			name: "error with additional properties",
			obj: ErrorObject{
				Err: "failed",
				AdditionalProperties: map[string]any{
					"code": 500,
				},
			},
			want: map[string]any{
				"error": "failed",
				"code":  float64(500),
			},
		},
		{
			name: "empty error string",
			obj:  ErrorObject{},
			want: map[string]any{"error": ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(&tt.obj)
			require.NoError(t, err)

			var got map[string]any
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestErrorObject_RoundTrip(t *testing.T) {
	t.Parallel()

	original := ErrorObject{
		Err: "validation error",
		AdditionalProperties: map[string]any{
			"field":  "email",
			"detail": "invalid format",
		},
	}

	data, err := json.Marshal(&original)
	require.NoError(t, err)

	var restored ErrorObject
	require.NoError(t, json.Unmarshal(data, &restored))

	assert.Equal(t, original.Err, restored.Err)
	for k, v := range original.AdditionalProperties {
		got, found := restored.Get(k)
		assert.True(t, found, "round-trip lost key %q", k)
		assert.Equal(t, v, got, "round-trip changed value for key %q", k)
	}
}

// ---------------------------------------------------------------------------
// APIError tests
// ---------------------------------------------------------------------------

func TestAPIError_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      APIError
		expected string
	}{
		{
			name: "with body",
			err: APIError{
				StatusCode: 404,
				Message:    "Not Found",
				Body:       `{"error":"resource not found"}`,
			},
			expected: "Not Found: Status 404\n{\"error\":\"resource not found\"}",
		},
		{
			name: "empty body",
			err: APIError{
				StatusCode: 500,
				Message:    "Internal Server Error",
				Body:       "",
			},
			expected: "Internal Server Error: Status 500",
		},
		{
			name:     "zero value",
			err:      APIError{},
			expected: ": Status 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

// ---------------------------------------------------------------------------
// SetTaskAbandonedError tests
// ---------------------------------------------------------------------------

func TestSetTaskAbandonedError_Error(t *testing.T) {
	t.Parallel()

	errMsg := "task already completed"

	tests := []struct {
		name        string
		err         SetTaskAbandonedError
		wantJSON    bool   // if true, output should be valid JSON
		wantContain string // substring to check in output
	}{
		{
			name: "with error and details produces JSON",
			err: SetTaskAbandonedError{
				Error_:  &errMsg,
				Details: []string{"already finished"},
			},
			wantJSON:    true,
			wantContain: "task already completed",
		},
		{
			name: "nil error with details produces JSON",
			err: SetTaskAbandonedError{
				Error_:  nil,
				Details: []string{"state mismatch"},
			},
			wantJSON:    true,
			wantContain: "state mismatch",
		},
		{
			name: "empty details produces JSON",
			err: SetTaskAbandonedError{
				Error_:  &errMsg,
				Details: []string{},
			},
			wantJSON:    true,
			wantContain: "task already completed",
		},
		{
			name:        "zero value produces JSON",
			err:         SetTaskAbandonedError{},
			wantJSON:    true,
			wantContain: "details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.err.Error()
			assert.Contains(t, result, tt.wantContain)
			if tt.wantJSON {
				assert.True(t, json.Valid([]byte(result)), "expected valid JSON, got: %s", result)
			}
		})
	}
}

func TestSetTaskAbandonedError_ErrorFallback(t *testing.T) {
	t.Parallel()

	// The fallback path is exercised when json.Marshal fails.
	// In practice, SetTaskAbandonedError always marshals successfully since
	// it only contains strings. We verify the normal path outputs valid JSON
	// and that the type implements the error interface correctly.
	errMsg := "some error"
	err := &SetTaskAbandonedError{
		Error_:  &errMsg,
		Details: []string{"detail1", "detail2"},
	}

	// Verify it implements error interface
	var e error = err
	assert.Contains(t, e.Error(), "some error")
	assert.Contains(t, e.Error(), "detail1")
}

package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUnwrapOr tests the UnwrapOr generic utility function.
func TestUnwrapOr(t *testing.T) {
	t.Run("nil pointer returns default", func(t *testing.T) {
		var p *string
		require.Equal(t, "default", UnwrapOr(p, "default"))
	})

	t.Run("non-nil pointer returns value", func(t *testing.T) {
		s := "hello"
		require.Equal(t, "hello", UnwrapOr(&s, "default"))
	})

	t.Run("nil int pointer returns default", func(t *testing.T) {
		var p *int
		require.Equal(t, 42, UnwrapOr(p, 42))
	})

	t.Run("non-nil int pointer returns value", func(t *testing.T) {
		v := 7
		require.Equal(t, 7, UnwrapOr(&v, 42))
	})

	t.Run("nil bool pointer returns default", func(t *testing.T) {
		var p *bool
		require.True(t, UnwrapOr(p, true))
	})

	t.Run("non-nil bool pointer returns value", func(t *testing.T) {
		v := false
		require.False(t, UnwrapOr(&v, true))
	})

	t.Run("zero value pointer returns zero not default", func(t *testing.T) {
		v := 0
		require.Equal(t, 0, UnwrapOr(&v, 99))
	})
}

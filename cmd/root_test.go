package cmd

import (
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
)

// newTestCommand creates a minimal Cobra command with a single canonical
// kebab-case flag and its deprecated underscore alias for testing.
func newTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(_ *cobra.Command, _ []string) {},
	}

	cmd.PersistentFlags().String("api-token", "", "API token")
	cmd.PersistentFlags().String("api_token", "", "")
	err := cmd.PersistentFlags().MarkDeprecated("api_token", "use --api-token instead")
	cobra.CheckErr(err)

	return cmd
}

// newMultiTypeTestCommand creates a command with all four flag types
// (string, bool, int, duration) and their deprecated aliases.
func newMultiTypeTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "test",
		Run: func(_ *cobra.Command, _ []string) {},
	}

	cmd.PersistentFlags().String("api-token", "", "API token")
	cmd.PersistentFlags().String("api_token", "", "")
	cobra.CheckErr(cmd.PersistentFlags().MarkDeprecated("api_token", "use --api-token instead"))

	cmd.PersistentFlags().Bool("extra-debugging", false, "Enable extra debugging")
	cmd.PersistentFlags().Bool("extra_debugging", false, "")
	cobra.CheckErr(cmd.PersistentFlags().MarkDeprecated("extra_debugging", "use --extra-debugging instead"))

	cmd.PersistentFlags().Int("status-timer", 10, "Status timer interval")
	cmd.PersistentFlags().Int("status_timer", 0, "")
	cobra.CheckErr(cmd.PersistentFlags().MarkDeprecated("status_timer", "use --status-timer instead"))

	cmd.PersistentFlags().Duration("sleep-on-failure", 60*time.Second, "Sleep on failure")
	cmd.PersistentFlags().Duration("sleep_on_failure", 0, "")
	cobra.CheckErr(cmd.PersistentFlags().MarkDeprecated("sleep_on_failure", "use --sleep-on-failure instead"))

	return cmd
}

func TestCanonicalFlagsAreKebabCase(t *testing.T) {
	flags := RootCmd.PersistentFlags()

	// Every non-deprecated flag name must be kebab-case (no underscores).
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Deprecated != "" {
			return // skip deprecated aliases
		}
		require.NotContains(t, f.Name, "_",
			"canonical flag %q contains underscore — should be kebab-case", f.Name)
	})
}

func TestDeprecatedAliasesRegistered(t *testing.T) {
	flags := RootCmd.PersistentFlags()

	for _, df := range deprecatedFlags {
		t.Run(df.oldName, func(t *testing.T) {
			old := flags.Lookup(df.oldName)
			require.NotNil(t, old, "deprecated alias %q not registered", df.oldName)
			require.NotEmpty(t, old.Deprecated, "flag %q should be marked deprecated", df.oldName)

			canonical := flags.Lookup(df.newName)
			require.NotNil(t, canonical, "canonical flag %q not registered", df.newName)
			require.Empty(t, canonical.Deprecated, "canonical flag %q should not be deprecated", df.newName)
		})
	}
}

func TestBridgeDeprecatedFlags_OldOnly(t *testing.T) {
	cmd := newTestCommand()
	args := []string{"--api_token", "old-value"}
	cmd.SetArgs(args)
	require.NoError(t, cmd.ParseFlags(args))

	bridgeDeprecatedFlags(cmd)

	canonical := cmd.PersistentFlags().Lookup("api-token")
	require.NotNil(t, canonical)
	require.Equal(t, "old-value", canonical.Value.String())
	require.True(t, canonical.Changed)
}

func TestBridgeDeprecatedFlags_NewOnly(t *testing.T) {
	cmd := newTestCommand()
	args := []string{"--api-token", "new-value"}
	cmd.SetArgs(args)
	require.NoError(t, cmd.ParseFlags(args))

	bridgeDeprecatedFlags(cmd)

	canonical := cmd.PersistentFlags().Lookup("api-token")
	require.NotNil(t, canonical)
	require.Equal(t, "new-value", canonical.Value.String())
	require.True(t, canonical.Changed)
}

func TestBridgeDeprecatedFlags_BothProvided_CanonicalWins(t *testing.T) {
	cmd := newTestCommand()
	args := []string{"--api_token", "old-value", "--api-token", "new-value"}
	cmd.SetArgs(args)
	require.NoError(t, cmd.ParseFlags(args))

	bridgeDeprecatedFlags(cmd)

	canonical := cmd.PersistentFlags().Lookup("api-token")
	require.NotNil(t, canonical)
	require.Equal(t, "new-value", canonical.Value.String(),
		"canonical flag value should take precedence over deprecated alias")
}

func TestBridgeDeprecatedFlags_BothProvided_ReverseOrder_CanonicalWins(t *testing.T) {
	cmd := newTestCommand()
	args := []string{"--api-token", "new-value", "--api_token", "old-value"}
	cmd.SetArgs(args)
	require.NoError(t, cmd.ParseFlags(args))

	bridgeDeprecatedFlags(cmd)

	canonical := cmd.PersistentFlags().Lookup("api-token")
	require.NotNil(t, canonical)
	require.Equal(t, "new-value", canonical.Value.String(),
		"canonical flag value should take precedence over deprecated alias")
}

func TestBridgeDeprecatedFlags_NeitherProvided(t *testing.T) {
	cmd := newTestCommand()
	cmd.SetArgs([]string{})
	require.NoError(t, cmd.ParseFlags([]string{}))

	bridgeDeprecatedFlags(cmd)

	canonical := cmd.PersistentFlags().Lookup("api-token")
	require.NotNil(t, canonical)
	require.Empty(t, canonical.Value.String())
	require.False(t, canonical.Changed)
}

func TestBridgeDeprecatedFlags_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		flagName string
		expected string
	}{
		{
			name:     "string type bridges correctly",
			args:     []string{"--api_token", "my-token"},
			flagName: "api-token",
			expected: "my-token",
		},
		{
			name:     "bool type bridges correctly",
			args:     []string{"--extra_debugging"},
			flagName: "extra-debugging",
			expected: "true",
		},
		{
			name:     "int type bridges correctly",
			args:     []string{"--status_timer", "42"},
			flagName: "status-timer",
			expected: "42",
		},
		{
			name:     "duration type bridges correctly",
			args:     []string{"--sleep_on_failure", "5m"},
			flagName: "sleep-on-failure",
			expected: "5m0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newMultiTypeTestCommand()
			cmd.SetArgs(tt.args)
			require.NoError(t, cmd.ParseFlags(tt.args))

			bridgeDeprecatedFlags(cmd)

			canonical := cmd.PersistentFlags().Lookup(tt.flagName)
			require.NotNil(t, canonical)
			require.Equal(t, tt.expected, canonical.Value.String())
			require.True(t, canonical.Changed)
		})
	}
}

package benchmark

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseHashInfoLine(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		wantID string
		wantOK bool
	}{
		{name: "MD5", line: "0 | MD5 | Raw Hash", wantID: "0", wantOK: true},
		{name: "SHA1", line: "100 | SHA1 | Raw Hash", wantID: "100", wantOK: true},
		{name: "NTLM", line: "1000 | NTLM | Raw Hash", wantID: "1000", wantOK: true},
		{name: "leading spaces", line: "  500 | md5crypt | Raw Hash", wantID: "500", wantOK: true},
		{name: "empty line", line: "", wantID: "", wantOK: false},
		{name: "comment line", line: "# Hash types supported", wantID: "", wantOK: false},
		{name: "header line", line: "Hash-Mode | Hash-Name | Description", wantID: "", wantOK: false},
		{name: "separator line", line: "------+----------+---------", wantID: "", wantOK: false},
		{name: "no pipe", line: "12345", wantID: "", wantOK: false},
		{name: "text before pipe", line: "abc | something", wantID: "", wantOK: false},
		{name: "large hash type", line: "99999 | SomeHash | Category", wantID: "99999", wantOK: true},
		{name: "tab separated", line: "\t200 | bcrypt | Hashes", wantID: "200", wantOK: true},
		{name: "only pipe", line: "|", wantID: "", wantOK: false},
		{name: "zero padded", line: "0100 | SomeType | Cat", wantID: "0100", wantOK: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, ok := parseHashInfoLine(tt.line)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantID, id)
			}
		})
	}
}

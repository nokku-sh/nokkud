package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteIfChangedErrors(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		data     []byte
		perm     os.FileMode
		wantErr  string
	}{
		{
			name:     "write new file successfully",
			filename: filepath.Join(tmpDir, "test.txt"),
			data:     []byte("hello world"),
			perm:     0o600,
		},
		{
			name:     "write empty data",
			filename: filepath.Join(tmpDir, "empty.txt"),
			data:     []byte{},
			perm:     0o600,
		},
		{
			name:     "write to existing file",
			filename: filepath.Join(tmpDir, "existing.txt"),
			data:     []byte("original"),
			perm:     0o600,
		},
		{
			name:     "overwrite existing file",
			filename: filepath.Join(tmpDir, "existing.txt"),
			data:     []byte("updated"),
			perm:     0o600,
		},
		{
			name:     "error empty filename",
			filename: "",
			data:     []byte("test"),
			perm:     0o600,
			wantErr:  "empty filename",
		},
		{
			name:     "error path is directory",
			filename: tmpDir,
			data:     []byte("test"),
			perm:     0o600,
			wantErr:  "not a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			is := assert.New(t)
			must := require.New(t)

			err := WriteIfChanged(tt.filename, tt.data, tt.perm)
			if tt.wantErr != "" {
				is.ErrorContains(err, tt.wantErr)
				return
			}
			must.NoError(err)

			got, readErr := os.ReadFile(tt.filename)
			must.NoError(readErr)
			is.Equal(tt.data, got)
		})
	}
}

func TestWriteIfChangedReportsWrites(t *testing.T) {
	t.Parallel()
	must := require.New(t)
	filename := filepath.Join(t.TempDir(), "wic.txt")

	must.NoError(WriteIfChanged(filename, []byte("a"), 0o600))
	must.NoError(WriteIfChanged(filename, []byte("a"), 0o600))
	must.NoError(WriteIfChanged(filename, []byte("bb"), 0o600))
}

package util

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteFile(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		data     []byte
		perm     os.FileMode
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "write new file successfully",
			filename: filepath.Join(tmpDir, "test.txt"),
			data:     []byte("hello world"),
			perm:     0o600,
			wantErr:  false,
		},
		{
			name:     "write empty data",
			filename: filepath.Join(tmpDir, "empty.txt"),
			data:     []byte{},
			perm:     0o600,
			wantErr:  false,
		},
		{
			name:     "write to existing file",
			filename: filepath.Join(tmpDir, "existing.txt"),
			data:     []byte("original"),
			perm:     0o600,
			wantErr:  false,
		},
		{
			name:     "overwrite existing file",
			filename: filepath.Join(tmpDir, "existing.txt"),
			data:     []byte("updated"),
			perm:     0o600,
			wantErr:  false,
		},
		{
			name:     "error empty filename",
			filename: "",
			data:     []byte("test"),
			perm:     0o600,
			wantErr:  true,
			errMsg:   "empty filename",
		},
		{
			name:     "error path is directory",
			filename: tmpDir,
			data:     []byte("test"),
			perm:     0o600,
			wantErr:  true,
			errMsg:   "not a regular file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := WriteFile(tt.filename, tt.data, tt.perm)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("WriteFile() error = %v, want error containing %q", err, tt.errMsg)
				}
				return
			}
			if !tt.wantErr {
				got, readErr := os.ReadFile(tt.filename)
				if readErr != nil {
					t.Errorf("WriteFile() created file but ReadFile failed: %v", readErr)
					return
				}
				if string(got) != string(tt.data) {
					t.Errorf("WriteFile() wrote %q, want %q", string(got), string(tt.data))
				}
			}
		})
	}
}

func TestFileExists(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()

	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "existing file returns true",
			path: func() string {
				f, _ := os.CreateTemp(tmpDir, "exist")
				_ = f.Close()
				return f.Name()
			}(),
			want: true,
		},
		{
			name: "non-existing file returns false",
			path: filepath.Join(tmpDir, "nonexistent.txt"),
			want: false,
		},
		{
			name: "directory returns false",
			path: tmpDir,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FileExists(tt.path); got != tt.want {
				t.Errorf("FileExists(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestWriteIfChangedReportsWrites(t *testing.T) {
	t.Parallel()
	filename := filepath.Join(t.TempDir(), "wic.txt")

	err := WriteIfChanged(filename, []byte("a"), 0o600)
	if err != nil {
		t.Fatalf("first write: err=%v", err)
	}

	err = WriteIfChanged(filename, []byte("a"), 0o600)
	if err != nil {
		t.Fatalf("second write: err=%v", err)
	}

	err = WriteIfChanged(filename, []byte("bb"), 0o600)
	if err != nil {
		t.Fatalf("third write: err=%v", err)
	}
}

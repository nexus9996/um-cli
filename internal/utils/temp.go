package utils

import (
	"fmt"
	"io"
	"os"
)

// WriteTempFile copies rd into a freshly created temp file and returns its
// path. On any error the partially written file is removed, so a failed copy
// cannot leak a file descriptor or a stale temp file.
func WriteTempFile(rd io.Reader, ext string) (string, error) {
	audioFile, err := os.CreateTemp("", "*"+ext)
	if err != nil {
		return "", fmt.Errorf("ffmpeg create temp file: %w", err)
	}

	name := audioFile.Name()
	fail := func(format string, err error) (string, error) {
		_ = audioFile.Close()
		_ = os.Remove(name)
		return "", fmt.Errorf(format+": %w", err)
	}

	if _, err := io.Copy(audioFile, rd); err != nil {
		return fail("ffmpeg write temp file", err)
	}

	if err := audioFile.Close(); err != nil {
		_ = os.Remove(name)
		return "", fmt.Errorf("ffmpeg close temp file: %w", err)
	}

	return name, nil
}

package output

import (
	"bytes"
	"io"
)

// BoundedWriter is an io.Writer that limits total written bytes to maxBytes.
// Excess bytes are discarded and Truncated flag is set to true.
type BoundedWriter struct {
	buf       bytes.Buffer
	maxBytes  int64
	written   int64
	Truncated bool
}

func NewBoundedWriter(maxBytes int64) *BoundedWriter {
	return &BoundedWriter{
		maxBytes: maxBytes,
	}
}

func (bw *BoundedWriter) Write(p []byte) (n int, err error) {
	n = len(p)
	if bw.maxBytes <= 0 {
		bw.buf.Write(p)
		bw.written += int64(len(p))
		return n, nil
	}

	remaining := bw.maxBytes - bw.written
	if remaining <= 0 {
		bw.Truncated = true
		return n, nil
	}

	if int64(len(p)) > remaining {
		bw.buf.Write(p[:remaining])
		bw.written += remaining
		bw.Truncated = true
		return n, nil
	}

	bw.buf.Write(p)
	bw.written += int64(len(p))
	return n, nil
}

func (bw *BoundedWriter) String() string {
	return bw.buf.String()
}

func (bw *BoundedWriter) Bytes() []byte {
	return bw.buf.Bytes()
}

// LimitString truncates a string to maxBytes safely and returns whether it was truncated.
func LimitString(s string, maxBytes int64) (string, bool) {
	if maxBytes <= 0 || int64(len(s)) <= maxBytes {
		return s, false
	}
	return s[:maxBytes], true
}

var _ io.Writer = (*BoundedWriter)(nil)

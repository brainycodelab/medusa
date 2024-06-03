package writer

import (
	"io"
	"os"
)

type DualWriter struct {
	writers []io.Writer
}

func (w *DualWriter) Write(p []byte) (n int, err error) {
	for _, writer := range w.writers {
		_, err = writer.Write(p)
		if err != nil {
			return n, err
		}
	}
	return len(p), nil
}

func NewDualWriter(buf io.Writer) *DualWriter {
	return &DualWriter{[]io.Writer{os.Stdout, buf}}
}

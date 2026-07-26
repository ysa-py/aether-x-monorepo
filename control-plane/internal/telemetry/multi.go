package telemetry

import "context"

// MultiWriter fans an event batch out to multiple Writers. A failure in any
// writer is recorded but does NOT abort the others (telemetry must not block on
// one slow sink). The first error encountered is returned so the caller can log
// it, while every writer still gets the batch.
type MultiWriter struct {
	writers []Writer
}

// NewMultiWriter composes Writers. Order is the write order.
func NewMultiWriter(writers ...Writer) *MultiWriter {
	return &MultiWriter{writers: writers}
}

// WriteBatch implements Writer.
func (m *MultiWriter) WriteBatch(ctx context.Context, events []Event) error {
	var firstErr error
	for _, w := range m.writers {
		if err := w.WriteBatch(ctx, events); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

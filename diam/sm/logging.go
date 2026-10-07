package sm

import (
	"context"
	"log/slog"

	"github.com/gomaja/go-diameter/diam"
)

// logMessage retains errors for errors.As and only exposes message headers.
func logMessage(c diam.Conn, m *diam.Message, level slog.Level, text string, err error) {
	ctx := c.Context()
	if m != nil {
		ctx = m.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}
	attrs := make([]slog.Attr, 0, 2)
	if m != nil {
		attrs = append(attrs, slog.Any("message", m))
	}
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
	}
	c.Logger().LogAttrs(ctx, level, text, attrs...)
}

// Copyright 2013-2026 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Package observe contains the panic boundary for synchronous protocol observers.
package observe

import (
	"log/slog"
	"runtime"
)

// Call invokes callback inline and recovers its panic into one Error record.
// A nil callback does no work. The caller must hold no bookkeeping locks.
func Call(logger *slog.Logger, callback func()) {
	if callback == nil {
		return
	}
	defer func() {
		if value := recover(); value != nil {
			LogPanic(logger, value)
		}
	}()
	callback()
}

// LogPanic records one recovered observation panic with a bounded stack.
func LogPanic(logger *slog.Logger, value any) {
	stack := make([]byte, 64<<10)
	stack = stack[:runtime.Stack(stack, false)]
	logger.Error("diam: protocol error callback panicked", slog.Any("panic", value), slog.String("stack", string(stack)))
}

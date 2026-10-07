package diam

// Plan 9 reports string errors rather than portable socket errno values.
// Timeout errors are handled by retryAcceptError; other errors are terminal.
func retryAcceptSystemError(error) bool { return false }

package sm

// mustNew keeps the test fixtures focused on the behavior under test. Tests
// for malformed configuration call New directly and inspect its error.
func mustNew(settings *Settings) *StateMachine {
	stateMachine, err := New(settings)
	if err != nil {
		panic(err)
	}
	return stateMachine
}

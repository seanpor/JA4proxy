package backup

func init() {
	// Reduce PBKDF2 iteration count to 1,000 in test mode so unit tests
	// and rapid property checks execute in milliseconds rather than timing out.
	pbkdf2Iterations = 1000
}

// SetPBKDF2IterationsForTest overrides the PBKDF2 iteration count for tests.
// Returns a cleanup function that restores the original iteration count.
func SetPBKDF2IterationsForTest(n int) func() {
	orig := pbkdf2Iterations
	pbkdf2Iterations = n
	return func() {
		pbkdf2Iterations = orig
	}
}

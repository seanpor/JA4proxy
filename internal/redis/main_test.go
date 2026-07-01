package redis

import (
	"context"
	"os"
	"testing"

	goredis "github.com/redis/go-redis/v9"
)

// voidLogger implements the go-redis internal.Logging interface, suppressing
// all go-redis pool/dial log output during tests (connection-refused noise
// from sentinel tests that have no running Sentinel).
type voidLogger struct{}

func (voidLogger) Printf(_ context.Context, _ string, _ ...interface{}) {}

func TestMain(m *testing.M) {
	goredis.SetLogger(voidLogger{})
	os.Exit(m.Run())
}

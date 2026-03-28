// Package redis provides the Redis client, Lua scripts, and pub/sub subscriber
// for the JA4proxy Go proxy.
package redis

import (
	_ "embed"
)

//go:embed scripts/sliding_window.lua
var SlidingWindowScript string

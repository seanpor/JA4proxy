// Copyright 2026 JA4proxy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tap

import (
	"fmt"
	"log"
	"runtime/debug"
)

// Recover wraps a goroutine to recover from panics, log the stack trace,
// close the sensor's events channel, and send an error to the done channel.
// It is used for the sensor's main goroutine to prevent hangs on panic.
func Recover(done chan<- error, s *Sensor) {
	if r := recover(); r != nil {
		log.Printf("tap sensor panic: %v\n%s", r, string(debug.Stack()))
		close(s.events)
		if done != nil {
			done <- fmt.Errorf("sensor panic: %v", r)
		}
	}
}
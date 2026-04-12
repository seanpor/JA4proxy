package logging

import (
	"bytes"

	"github.com/sirupsen/logrus"
)

// DualFormatter emits two newline-separated JSON log lines per entry:
// a legacy logrus JSON line followed by an ECS 8.x line.
// Used during the transition period when logging.dual_output: true.
type DualFormatter struct {
	Legacy logrus.Formatter // emits legacy format
	ECS    logrus.Formatter // emits ECS format
}

// Format implements logrus.Formatter.
func (d *DualFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	legacyBytes, err := d.Legacy.Format(entry)
	if err != nil {
		return nil, err
	}
	ecsBytes, err := d.ECS.Format(entry)
	if err != nil {
		return nil, err
	}
	// Both formatters already append a trailing newline.
	// Strip the trailing newline from the legacy line before joining.
	legacy := bytes.TrimRight(legacyBytes, "\n")
	return append(append(legacy, '\n'), ecsBytes...), nil
}

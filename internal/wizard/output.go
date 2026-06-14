package wizard

import (
	"fmt"
	"os"
)

type Output interface {
	Header(text string)
	Section(text string)
	Info(format string, args ...interface{})
	Warn(format string, args ...interface{})
	Success(format string, args ...interface{})
	Raw(text string) // for content preview (no format string)
}

type ConsoleOutput struct {
	NoColor bool
}

func NewConsoleOutput() *ConsoleOutput {
	_, noColor := os.LookupEnv("NO_COLOR")
	return &ConsoleOutput{NoColor: noColor}
}

const (
	colorReset  = "\033[0m"
	colorBlue   = "\033[34m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

func (c *ConsoleOutput) color(code, text string) string {
	if c.NoColor {
		return text
	}
	return code + text + colorReset
}

func (c *ConsoleOutput) Header(text string) {
	fmt.Println()
	fmt.Println(c.color(colorCyan+colorBold, "="+stringsRepeat("=", len(text)+1)+"="))
	fmt.Println(c.color(colorCyan+colorBold, " "+text+" "))
	fmt.Println(c.color(colorCyan+colorBold, "="+stringsRepeat("=", len(text)+1)+"="))
	fmt.Println()
}

func (c *ConsoleOutput) Section(text string) {
	fmt.Println()
	fmt.Println(c.color(colorBlue+colorBold, "── "+text+" ──"))
	fmt.Println()
}

func (c *ConsoleOutput) Info(format string, args ...interface{}) {
	fmt.Printf("  "+format+"\n", args...)
}

func (c *ConsoleOutput) Warn(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, c.color(colorYellow, "  ⚠ "+msg))
}

func (c *ConsoleOutput) Success(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(c.color(colorGreen, "  ✓ "+msg))
}

func (c *ConsoleOutput) Raw(text string) {
	fmt.Println(text)
}

func stringsRepeat(s string, n int) string {
	result := make([]byte, len(s)*n)
	for i := range result {
		result[i] = s[i%len(s)]
	}
	return string(result)
}

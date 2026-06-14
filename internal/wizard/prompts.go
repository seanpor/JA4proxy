package wizard

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func ask(prompt, defaultVal string, validate func(string) bool, inputFn func(string) (string, error)) (string, error) {
	for {
		suffix := fmt.Sprintf(" [%s]: ", defaultVal)
		if defaultVal == "" {
			suffix = ": "
		}
		input, err := inputFn(prompt + suffix)
		if err != nil {
			return "", err
		}
		input = strings.TrimSpace(input)
		if input == "" {
			input = defaultVal
		}
		if validate(input) {
			return input, nil
		}
		fmt.Fprintf(os.Stderr, "  invalid value, try again\n")
	}
}

func askYesNo(prompt string, defaultYes bool, inputFn func(string) (string, error)) (bool, error) {
	defaultStr := "y/N"
	if defaultYes {
		defaultStr = "Y/n"
	}
	val, err := ask(prompt+" (y/n)", defaultStr,
		func(s string) bool {
			switch strings.ToLower(s) {
			case "y", "yes", "n", "no", "y/n", "n/y":
				return true
			}
			return false
		}, inputFn)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(val) {
	case "y", "yes", "y/n":
		return true, nil
	default:
		return false, nil
	}
}

func StdinInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func StdinGetPass(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

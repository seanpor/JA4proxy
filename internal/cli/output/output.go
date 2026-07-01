// Package output provides helpers for rendering CLI results as ASCII tables,
// JSON, or CSV.  All functions return the rendered string so callers can
// write to any destination or capture output in tests.
package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/olekukonko/tablewriter"
)

// fieldNames returns the struct field names of the element type of data.
// data must be a slice of structs (or pointers to structs).
func fieldNames(data interface{}) ([]string, error) {
	t := reflect.TypeOf(data)
	if t == nil {
		return nil, fmt.Errorf("data is nil")
	}
	if t.Kind() != reflect.Slice {
		return nil, fmt.Errorf("data must be a slice, got %s", t.Kind())
	}
	elem := t.Elem()
	if elem.Kind() == reflect.Pointer {
		elem = elem.Elem()
	}
	if elem.Kind() != reflect.Struct {
		return nil, fmt.Errorf("slice element must be a struct, got %s", elem.Kind())
	}
	names := make([]string, elem.NumField())
	for i := range elem.NumField() {
		names[i] = elem.Field(i).Name
	}
	return names, nil
}

// rows converts a slice of structs into a 2-D string grid for tabular display.
func rows(data interface{}) [][]string {
	v := reflect.ValueOf(data)
	result := make([][]string, v.Len())
	for i := range v.Len() {
		elem := v.Index(i)
		if elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		row := make([]string, elem.NumField())
		for j := range elem.NumField() {
			row[j] = fmt.Sprintf("%v", elem.Field(j).Interface())
		}
		result[i] = row
	}
	return result
}

// RenderTable renders a slice of structs as an ASCII table using tablewriter.
// Headers are derived from exported struct field names.
// data must be a slice of structs (not a pointer to a slice).
// Returns the rendered table as a string.
func RenderTable(data interface{}) (string, error) {
	headers, err := fieldNames(data)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	table := tablewriter.NewWriter(&buf)
	table.Header(headers)
	for _, row := range rows(data) {
		_ = table.Append(row)
	}
	_ = table.Render()
	return buf.String(), nil
}

// RenderJSON renders data as indented JSON and returns the result as a string.
func RenderJSON(data interface{}) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderCSV renders a slice of structs as CSV with a header row and returns
// the result as a string.  data must be a slice of structs.
func RenderCSV(data interface{}) (string, error) {
	headers, err := fieldNames(data)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	if err := cw.Write(headers); err != nil {
		return "", err
	}
	for _, row := range rows(data) {
		if err := cw.Write(row); err != nil {
			return "", err
		}
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// WriteTo writes s to w.  It is a thin helper used by main.go to write a
// rendered string to os.Stdout (or any io.Writer).
func WriteTo(w io.Writer, s string) error {
	_, err := io.WriteString(w, strings.TrimRight(s, "\n")+"\n")
	return err
}

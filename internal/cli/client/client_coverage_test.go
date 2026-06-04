package client_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/client"
)

// TestClient_Patch_SetsMethodAndBody verifies Patch sends the correct HTTP method
// and JSON body.
func TestClient_Patch_SetsMethodAndBody(t *testing.T) {
	var gotMethod string
	var gotBody map[string]interface{}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "patch-token")
	body := map[string]interface{}{"setting": 42}
	var out map[string]interface{}
	err := c.Patch(context.Background(), "/api/v1/dial", body, &out)
	if err != nil {
		t.Fatalf("Patch error: %v", err)
	}
	if gotMethod != http.MethodPatch {
		t.Errorf("method = %q; want PATCH", gotMethod)
	}
	if gotBody["setting"] != float64(42) {
		t.Errorf("body.setting = %v; want 42", gotBody["setting"])
	}
	if out["status"] != "ok" {
		t.Errorf("response status = %v; want ok", out["status"])
	}
}

// TestClient_Patch_SetsAuthHeader verifies Patch carries the auth header.
func TestClient_Patch_SetsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "my-patch-token")
	err := c.Patch(context.Background(), "/api/v1/test", nil, nil)
	if err != nil {
		t.Fatalf("Patch error: %v", err)
	}
	if gotAuth != "Bearer my-patch-token" {
		t.Errorf("Authorization = %q; want %q", gotAuth, "Bearer my-patch-token")
	}
}

// TestClient_Patch_ErrorOnNon2xx verifies Patch returns an error for 4xx/5xx.
func TestClient_Patch_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := c.Patch(context.Background(), "/api/v1/test", nil, nil)
	if err == nil {
		t.Fatal("expected error for 403; got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error %q does not contain 403", err.Error())
	}
}

// TestClient_PostBinaryResponse_ReturnsBytes verifies PostBinaryResponse returns
// raw bytes and content type.
func TestClient_PostBinaryResponse_ReturnsBytes(t *testing.T) {
	fakeZip := []byte("PK\x03\x04fake-zip")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q; want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(fakeZip)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	body := map[string]string{"since": "2026-01-01", "until": "2026-04-01"}
	data, ct, err := c.PostBinaryResponse(context.Background(), "/api/v1/export", body)
	if err != nil {
		t.Fatalf("PostBinaryResponse error: %v", err)
	}
	if ct != "application/zip" {
		t.Errorf("content-type = %q; want application/zip", ct)
	}
	if string(data) != string(fakeZip) {
		t.Errorf("data mismatch: got %q, want %q", data, fakeZip)
	}
}

// TestClient_PostBinaryResponse_ErrorOnNon2xx verifies error for non-2xx responses.
func TestClient_PostBinaryResponse_ErrorOnNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"server error"}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, _, err := c.PostBinaryResponse(context.Background(), "/api/v1/export", nil)
	if err == nil {
		t.Fatal("expected error for 500; got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error %q does not contain 500", err.Error())
	}
}

// TestClient_PostBinaryResponse_LongErrorBodyTruncated verifies that a very long
// error body is truncated in the error message.
func TestClient_PostBinaryResponse_LongErrorBodyTruncated(t *testing.T) {
	longBody := strings.Repeat("x", 500)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(longBody))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	_, _, err := c.PostBinaryResponse(context.Background(), "/test", nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "...") {
		t.Errorf("long error body should be truncated with '...': %s", err.Error())
	}
}

// TestClient_Post_ErrorOn500 verifies Post returns descriptive error for 500.
func TestClient_Post_ErrorOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	err := c.Post(context.Background(), "/api/v1/bans/1.2.3.4", map[string]int{"ttl": 60}, nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error should mention 500: %s", err.Error())
	}
}

// TestClient_Post_DecodesResponse verifies Post decodes JSON response into out.
func TestClient_Post_DecodesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"1.2.3.4","ttl":3600}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	var out map[string]interface{}
	err := c.Post(context.Background(), "/api/v1/bans/1.2.3.4", map[string]int{"ttl": 3600}, &out)
	if err != nil {
		t.Fatalf("Post error: %v", err)
	}
	if out["ip"] != "1.2.3.4" {
		t.Errorf("ip = %v; want 1.2.3.4", out["ip"])
	}
}

// TestClient_Get_InvalidJSON verifies Get returns error for invalid JSON response.
func TestClient_Get_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "token")
	var out map[string]interface{}
	err := c.Get(context.Background(), "/api/v1/test", &out)
	if err == nil {
		t.Fatal("expected error for invalid JSON response")
	}
	if !strings.Contains(err.Error(), "decoding") {
		t.Errorf("error should mention decoding: %s", err.Error())
	}
}

// TestClient_NoToken_OmitsAuthHeader verifies that when token is empty, no
// Authorization header is sent.
func TestClient_NoToken_OmitsAuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := client.New(srv.URL, "")
	_ = c.Get(context.Background(), "/test", nil)
	if gotAuth != "" {
		t.Errorf("expected no Authorization header when token is empty; got %q", gotAuth)
	}
}

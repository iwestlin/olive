package web

import (
	"encoding/json"
	"net/http"

	"github.com/dimfeld/httptreemux/v5"
)

// Param returns the web call parameters from the request.
func Param(r *http.Request, key string) string {
	m := httptreemux.ContextParams(r.Context())
	return m[key]
}

// MaxBodyBytes caps the size of any incoming JSON request body. Without a
// limit an anonymous client can pin the process memory by streaming a 1GB
// JSON document into Decode; 1 MiB comfortably covers every payload produced
// by the portal while still bounding resource use.
const MaxBodyBytes int64 = 1 << 20 // 1 MiB

// Decode reads the body of an HTTP request looking for a JSON document. The
// body is decoded into the provided value. The body is also capped at
// MaxBodyBytes to prevent trivial memory exhaustion DoS.
//
// If the provided value is a struct then it is checked for validation tags.
func Decode(r *http.Request, val any) error {
	body := http.MaxBytesReader(nil, r.Body, MaxBodyBytes)
	defer body.Close()

	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(val); err != nil {
		return err
	}

	return nil
}

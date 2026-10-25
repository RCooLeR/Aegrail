package httpadapter

import (
	"encoding/json/v2"
	"io"
	"net/http"
)

const maxJSONRequestBodyBytes int64 = 1 << 20

// decodeJSONBody keeps every dashboard mutation on the same strict JSON
// contract. JSON v2 rejects duplicate object names, invalid UTF-8, and trailing
// values by default; rejecting unknown members also catches stale clients and
// misspelled fields instead of silently ignoring them.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, out any) error {
	if r == nil || r.Body == nil {
		return io.EOF
	}
	return json.UnmarshalRead(
		http.MaxBytesReader(w, r.Body, maxJSONRequestBodyBytes),
		out,
		json.RejectUnknownMembers(true),
	)
}

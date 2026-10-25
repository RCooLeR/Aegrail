package httpadapter

import (
	"net/http"
	"strconv"
	"strings"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// apiCompressionMiddleware limits dynamic compression to API responses. Static
// dashboard files keep their native range and caching behavior, while the
// larger findings, inventory, and traffic payloads benefit from Go 1.27's
// faster DEFLATE implementation.
func apiCompressionMiddleware(next http.Handler) http.Handler {
	compressed := chimiddleware.Compress(5)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r != nil && r.URL != nil && strings.HasPrefix(r.URL.Path, "/api/") {
			// chi's compressor currently uses substring matching and does not
			// account for q=0. Normalize the header to exact, acceptable tokens
			// before delegating so a client can explicitly refuse an encoding.
			request := r.Clone(r.Context())
			request.Header.Set("Accept-Encoding", preferredAcceptEncoding(r.Header.Get("Accept-Encoding")))
			compressed.ServeHTTP(w, request)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func preferredAcceptEncoding(header string) string {
	if strings.TrimSpace(header) == "" {
		return ""
	}
	qualities := make(map[string]float64, 4)
	validNames := map[string]bool{"gzip": true, "deflate": true, "identity": true, "*": true}
	for value := range strings.SplitSeq(strings.ToLower(header), ",") {
		parts := strings.Split(value, ";")
		name := strings.TrimSpace(parts[0])
		if !validNames[name] {
			continue
		}
		quality := 1.0
		valid := true
		for _, parameter := range parts[1:] {
			key, raw, found := strings.Cut(strings.TrimSpace(parameter), "=")
			if !found || strings.TrimSpace(key) != "q" {
				continue
			}
			parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
			if err != nil || parsed < 0 || parsed > 1 {
				valid = false
				break
			}
			quality = parsed
		}
		if valid {
			qualities[name] = quality
		}
	}

	wildcard, hasWildcard := qualities["*"]
	qualityFor := func(name string) float64 {
		if quality, found := qualities[name]; found {
			return quality
		}
		if hasWildcard {
			return wildcard
		}
		return 0
	}
	identity := 1.0
	if explicit, found := qualities["identity"]; found {
		identity = explicit
	} else if hasWildcard && wildcard == 0 {
		identity = 0
	}

	// Prefer gzip on equal weights, then deflate, matching chi's server-side
	// precedence. Identity wins only when the client assigned it a strictly
	// higher quality than every supported coding.
	bestName := "gzip"
	bestQuality := qualityFor(bestName)
	if deflateQuality := qualityFor("deflate"); deflateQuality > bestQuality {
		bestName = "deflate"
		bestQuality = deflateQuality
	}
	if bestQuality <= 0 || identity > bestQuality {
		return ""
	}
	return bestName
}

// Package redact removes secret material from item fields.
package redact

import (
	"regexp"
	"strings"

	"agpass/internal/api"
)

// scheme://user:password@ — password group is replaced. The password runs
// to the last '@' before whitespace, so an unencoded '@' in it (p@ss@host)
// is covered. When a later '@' appears in the path or query, more than the
// password is redacted, never less.
var urlPassword = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://[^\s/:@]*:)(\S+)@`)

// scheme://longtoken@ — a userinfo without password that looks like a token
// (e.g. https://ghp_xxx@github.com).
var urlTokenUser = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://)([^\s/:@]{20,})@`)

var queryParam = regexp.MustCompile(`(?i)([?&;](?:password|passwd|pwd|pass|token|access_token|refresh_token|id_token|api[_-]?key|apikey|secret|client_secret|sig|signature|sslpassword|auth|authorization|key)=)([^&#\s]+)`)

// Secret reports whether a field of type t is redacted as a whole.
func Secret(t string) bool {
	return t == api.TypeSensitive || t == api.TypePassword
}

// String redacts credentials embedded in URLs inside s.
func String(s string) string {
	s = urlPassword.ReplaceAllString(s, "${1}"+api.Redacted+"@")
	s = urlTokenUser.ReplaceAllString(s, "${1}"+api.Redacted+"@")
	s = queryParam.ReplaceAllString(s, "${1}"+api.Redacted)
	return s
}

// Fields returns a redacted copy: secret-typed values are replaced entirely,
// all other values have URL credentials removed and any occurrence of a
// secret value from the same item scrubbed.
func Fields(in []api.Field) []api.Field {
	var secrets []string
	for _, f := range in {
		if Secret(f.Type) && len(f.Value) >= 4 {
			secrets = append(secrets, f.Value)
		}
	}
	out := make([]api.Field, len(in))
	for i, f := range in {
		if Secret(f.Type) {
			f.Value = api.Redacted
		} else {
			f.Value = String(scrub(f.Value, secrets))
		}
		out[i] = f
	}
	return out
}

// scrub replaces every byte of s covered by an occurrence of any secret.
// Occurrences are found in the original text and merged, so overlapping or
// nested secrets (one a prefix of another) leave no fragment behind.
func scrub(s string, secrets []string) string {
	if len(secrets) == 0 {
		return s
	}
	covered := make([]bool, len(s))
	found := false
	for _, sec := range secrets {
		for off := 0; ; {
			i := strings.Index(s[off:], sec)
			if i < 0 {
				break
			}
			start := off + i
			for j := start; j < start+len(sec); j++ {
				covered[j] = true
			}
			found = true
			off = start + 1 // overlapping occurrences too
		}
	}
	if !found {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if !covered[i] {
			b.WriteByte(s[i])
			i++
			continue
		}
		b.WriteString(api.Redacted)
		for i < len(s) && covered[i] {
			i++
		}
	}
	return b.String()
}

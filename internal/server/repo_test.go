package server

import "testing"

func TestNormalizeRepo(t *testing.T) {
	cases := map[string]string{
		"git@github.com:Acme/CRM.git":             "github.com/acme/crm",
		"https://github.com/acme/crm":             "github.com/acme/crm",
		"https://github.com/acme/crm.git/":        "github.com/acme/crm",
		"https://x-access-token:t@github.com/a/b": "github.com/a/b",
		"ssh://git@github.com/acme/crm.git":       "github.com/acme/crm",
		"github.com/acme/crm":                     "github.com/acme/crm",
		"":                                        "",
	}
	for in, want := range cases {
		if got := NormalizeRepo(in); got != want {
			t.Errorf("NormalizeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

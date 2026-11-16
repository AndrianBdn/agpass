package redact

import (
	"testing"

	"agpass/internal/api"
)

const R = api.Redacted

func TestString(t *testing.T) {
	cases := map[string]string{
		"postgres://app:s3cr3t@db:5432/crm":                    "postgres://app:" + R + "@db:5432/crm",
		"postgresql://app:p%40ss/w@db/crm?sslmode=require":     "postgresql://app:" + R + "@db/crm?sslmode=require",
		"https://user:pw@example.com/x":                        "https://user:" + R + "@example.com/x",
		"https://ghp_aaaaaaaaaaaaaaaaaaaaaaaa@github.com/x/y":  "https://" + R + "@github.com/x/y",
		"https://bob@example.com":                              "https://bob@example.com",
		"https://api.example.com/v1?api_key=abc123&x=1":        "https://api.example.com/v1?api_key=" + R + "&x=1",
		"redis://:hunter2@cache:6379/0":                        "redis://:" + R + "@cache:6379/0",
		"DATABASE_URL=mysql://root:toor@localhost/db and more": "DATABASE_URL=mysql://root:" + R + "@localhost/db and more",
		"plain text": "plain text",
	}
	for in, want := range cases {
		if got := String(in); got != want {
			t.Errorf("String(%q)\n got  %q\n want %q", in, got, want)
		}
	}
}

func TestFields(t *testing.T) {
	in := []api.Field{
		{Key: "user", Type: api.TypeText, Value: "app"},
		{Key: "password", Type: api.TypePassword, Value: "s3cr3t-pw"},
		{Key: "token", Type: api.TypeSensitive, Value: "tok_live_123"},
		{Key: "dsn", Type: api.TypeText, Value: "host=db password=s3cr3t-pw"},
		{Key: "url", Type: api.TypeURL, Value: "postgres://app:other@db/crm"},
	}
	out := Fields(in)
	want := []string{"app", R, R, "host=db password=" + R, "postgres://app:" + R + "@db/crm"}
	for i, f := range out {
		if f.Value != want[i] {
			t.Errorf("%s: got %q want %q", f.Key, f.Value, want[i])
		}
	}
	if in[1].Value != "s3cr3t-pw" {
		t.Error("input mutated")
	}
}

func TestFieldsOverlappingSecrets(t *testing.T) {
	cases := []struct {
		secrets []string
		text    string
		want    string
	}{
		{[]string{"abcd", "abcdef123456"}, "x abcdef123456 y", "x " + R + " y"},
		{[]string{"abcdef123456", "abcd"}, "x abcdef123456 y", "x " + R + " y"},
		{[]string{"xxabc", "abcyy"}, "xxabcyy", R},
		{[]string{"aaaa"}, "aaaaaa", R},
		{[]string{"abcd"}, "abcd-abcd", R + "-" + R},
	}
	for _, c := range cases {
		in := []api.Field{{Key: "note", Type: api.TypeText, Value: c.text}}
		for i, s := range c.secrets {
			in = append(in, api.Field{Key: string(rune('a' + i)), Type: api.TypeSensitive, Value: s})
		}
		if got := Fields(in)[0].Value; got != c.want {
			t.Errorf("secrets %q in %q: got %q want %q", c.secrets, c.text, got, c.want)
		}
	}
}

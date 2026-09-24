package render

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/util"
)

func ctx() Context {
	return Context{
		Seq:       7,
		BatchIdx:  2,
		Iteration: 1,
		Actor:     "alice",
		Timestamp: time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC),
		Variables: map[string]string{"host": "evil.test"},
	}
}

func TestApplyResolvesEveryToken(t *testing.T) {
	util.Seed(1)
	got, err := Apply("${SEQ}|${BATCH}|${ITER}|${ACTOR}|${VAR:host}|${DATE:2006-01-02}|${IP}", ctx())
	if err != nil {
		t.Fatal(err)
	}
	if want := "7|2|1|alice|evil.test|2026-03-11|192.168.0.7"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	for _, tok := range []string{"${RND:8}", "${RANDOM:4}", "${UUID}", "${HASH:12}"} {
		out, err := Apply(tok, ctx())
		if err != nil || strings.Contains(out, "${") || out == "" {
			t.Errorf("%s -> %q, %v", tok, out, err)
		}
	}
}

func TestApplyErrors(t *testing.T) {
	manifest := ctx()
	manifest.Actor = ""
	for _, tc := range []struct {
		in   string
		c    Context
		want string
	}{
		{"x_${VAR:nope}.txt", ctx(), `undefined variable "nope"`},
		{"${RAND:8}", ctx(), "unknown token ${RAND:8}"},
		{"${RND:0}", ctx(), "length must be at least 1"},
		{"${HASH:0}", ctx(), "length must be at least 1"},
		{"${UUID", ctx(), "unterminated token"},
		{"${ACTOR}", manifest, "only defined in playbooks"},
	} {
		if _, err := Apply(tc.in, tc.c); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Apply(%q) err = %v, want %q", tc.in, err, tc.want)
		}
	}
}

func TestDollarEscapeIsLiteral(t *testing.T) {
	got, err := Apply(`echo "$${HOME}" ${VAR:host} $${VAR:host}`, ctx())
	if err != nil {
		t.Fatal(err)
	}
	if want := `echo "${HOME}" evil.test ${VAR:host}`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// The order of random draws fixes the bytes a seed produces: random strings
// are drawn before UUIDs and hashes regardless of where they sit in the
// string. Reordering the rules must be a deliberate, versioned change.
func TestDrawOrderIsFixed(t *testing.T) {
	util.Seed(99)
	mixed, err := Apply("${HASH:4}-${RND:4}", ctx())
	if err != nil {
		t.Fatal(err)
	}
	util.Seed(99)
	rnd := util.GetRandomString(4)
	hash := util.GetRandomHex(4)
	if mixed != hash+"-"+rnd {
		t.Errorf("got %q, want %q (RND drawn before HASH)", mixed, hash+"-"+rnd)
	}
}

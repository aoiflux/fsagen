package render

import (
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

func ctx() Context {
	return Context{
		Seq:       7,
		BatchIdx:  2,
		Iteration: 1,
		Actor:     "alice",
		Timestamp: time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC),
		Variables: map[string]string{"host": "evil.test"},
		Rand:      prng.Root(1).Derive("op"),
		Field:     "path",
	}
}

func TestApplyResolvesEveryToken(t *testing.T) {
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
	undated := ctx()
	undated.Timestamp = time.Time{}
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
		{"${DATE:2006}", undated, "has no reference time"},
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

func apply(t *testing.T, s string, c Context) string {
	t.Helper()
	out, err := Apply(s, c)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A random token's value depends on its kind, its position among tokens of
// that kind in its field, the field and the operation, and nothing else:
// other tokens around it do not shift it.
func TestTokenDrawIndependentOfOtherFields(t *testing.T) {
	c := ctx()
	alone := apply(t, "${RND:6}", c)
	if mixed := apply(t, "${HASH:4}-${UUID}-${RND:6}", c); !strings.HasSuffix(mixed, "-"+alone) {
		t.Errorf("an RND after other kinds of token changed: %q vs %q", mixed, alone)
	}
	hash := apply(t, "${HASH:8}", c)
	if mixed := apply(t, "${RND:6}-${UUID}-${HASH:8}", c); !strings.HasSuffix(mixed, "-"+hash) {
		t.Errorf("a HASH after other kinds of token changed: %q vs %q", mixed, hash)
	}
	if again := apply(t, "${RND:6}", c); again != alone {
		t.Errorf("same token, same field: %q then %q", alone, again)
	}
	two := apply(t, "${RND:6}/${RND:6}", c)
	if !strings.HasPrefix(two, alone+"/") || strings.HasSuffix(two, "/"+alone) {
		t.Errorf("second RND in a field should differ from the first: %q", two)
	}
	other := c
	other.Field = "content"
	if apply(t, "${RND:6}", other) == alone {
		t.Error("the same token in another field drew the same value")
	}
	otherOp := c
	otherOp.Rand = prng.Root(1).Derive("another op")
	if apply(t, "${RND:6}", otherOp) == alone {
		t.Error("the same token in another operation drew the same value")
	}
	if hash := apply(t, "${HASH:40}", c); strings.Trim(hash, "0123456789abcdef") != "" {
		t.Errorf("HASH is not lowercase hex: %q", hash)
	}
}

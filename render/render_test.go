package render

import (
	"net/netip"
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

// TestIPStaysInCIDR: ${IP:block} draws an address inside the block from the
// operation's own stream, never the network or broadcast address of an IPv4
// block that has them, and the same seed gives the same address.
func TestIPStaysInCIDR(t *testing.T) {
	for _, tc := range []struct{ cidr, prefix string }{
		{"10.0.0.0/8", "10."},
		{"192.168.4.0/24", "192.168.4."},
		{"172.16.0.0/12", "172."},
		{"203.0.113.5/32", "203.0.113.5"},
		{"2001:db8::/32", "2001:db8:"},
	} {
		seen := map[string]bool{}
		for i := 0; i < 32; i++ {
			ctx := Context{Rand: prng.Root(int64(i)), Field: "path"}
			got, err := Apply("host-${IP:"+tc.cidr+"}", ctx)
			if err != nil {
				t.Fatalf("%s: %v", tc.cidr, err)
			}
			addr := strings.TrimPrefix(got, "host-")
			if !strings.HasPrefix(addr, tc.prefix) {
				t.Fatalf("%s gave %s, which is outside the block", tc.cidr, addr)
			}
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				t.Fatalf("%s gave %q, which is not an address: %v", tc.cidr, addr, err)
			}
			if !netip.MustParsePrefix(tc.cidr).Masked().Contains(ip) {
				t.Fatalf("%s is not inside %s", addr, tc.cidr)
			}
			// The block's own first and last addresses are the network and
			// broadcast, which no host has.
			block := netip.MustParsePrefix(tc.cidr).Masked()
			if ip.Is4() && block.Bits() <= 30 && (ip == block.Addr() || ip == lastAddr(block)) {
				t.Errorf("%s is the network or broadcast address of %s", addr, tc.cidr)
			}
			seen[addr] = true
		}
		if len(seen) < 2 && !strings.HasSuffix(tc.cidr, "/32") {
			t.Errorf("%s gave only %v for 32 different seeds", tc.cidr, seen)
		}
	}
	// A block small enough to enumerate. Thirty-two draws from a /8 would
	// almost never land on the network or broadcast address, so only a block
	// with four addresses in it shows whether they are left out at all.
	for _, tc := range []struct {
		cidr string
		want []string
	}{
		{"10.1.2.0/30", []string{"10.1.2.1", "10.1.2.2"}},
		// A /31 is a point-to-point link: both of its addresses are hosts.
		{"10.1.2.4/31", []string{"10.1.2.4", "10.1.2.5"}},
	} {
		seen := map[string]bool{}
		for i := 0; i < 200; i++ {
			got, err := Apply("${IP:"+tc.cidr+"}", Context{Rand: prng.Root(int64(i)), Field: "path"})
			if err != nil {
				t.Fatalf("%s: %v", tc.cidr, err)
			}
			seen[got] = true
		}
		if len(seen) != len(tc.want) {
			t.Errorf("%s gave %v, want exactly %v", tc.cidr, seen, tc.want)
		}
		for _, w := range tc.want {
			if !seen[w] {
				t.Errorf("%s never gave %s", tc.cidr, w)
			}
		}
	}

	// The same key gives the same address, every time.
	ctx := Context{Rand: prng.Root(7), Field: "path"}
	first, err := Apply("${IP:10.0.0.0/8}", ctx)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := Apply("${IP:10.0.0.0/8}", ctx); again != first {
		t.Errorf("%s then %s", first, again)
	}
	// A block that is not one is an error, not a silent empty string.
	for _, bad := range []string{"${IP:notacidr}", "${IP:10.0.0.0}", "${IP:10.0.0.0/33}"} {
		if _, err := Apply(bad, ctx); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	// Bare ${IP} still walks 192.168.x.y from the sequence number.
	got, err := Apply("${IP}", Context{Seq: 5})
	if err != nil || got != "192.168.0.5" {
		t.Errorf("${IP} = %q (%v)", got, err)
	}
}

// lastAddr is the all-ones host address of a block: its broadcast for IPv4.
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i, host := len(b)-1, p.Addr().BitLen()-p.Bits(); host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(0xff) >> (8 - n)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

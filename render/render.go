// Package render implements the ${...} token substitution shared by manifests
// and playbooks.
//
// Substitution is strict: an undefined variable, an unknown or malformed
// token, or any "${" left over after every rule has run is an error. A token
// that reaches the output verbatim is silently wrong data (and a ':' inside
// one used to create an NTFS alternate data stream). Write "$${" for a literal
// "${".
package render

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// Context supplies the values that tokens resolve against. Manifests leave
// Actor, BatchIdx and Iteration at their zero values.
type Context struct {
	Seq       int
	BatchIdx  int
	Iteration int
	Actor     string
	// Timestamp is what ${DATE:...} formats. Zero means the operation has no
	// reference time, and ${DATE} is an error.
	Timestamp time.Time
	Variables map[string]string
	// Rand is the operation's key and Field the name of the field being
	// rendered. The n-th random token of a kind in that field draws from
	// Rand.Derive("token", Field, kind, n), so its value depends on nothing
	// else in the scenario.
	Rand  prng.Key
	Field string
}

// draw returns the stream for the n-th token of kind in the current field.
func (c Context) draw(kind string, n int) *prng.Stream {
	return c.Rand.Derive("token", c.Field, kind, strconv.Itoa(n)).Stream()
}

var (
	reRnd   = regexp.MustCompile(`\$\{(RND|RANDOM)\:(\d+)\}`)
	reSeq   = regexp.MustCompile(`\$\{SEQ\}`)
	reDate  = regexp.MustCompile(`\$\{DATE\:([^}]+)\}`)
	reActor = regexp.MustCompile(`\$\{ACTOR\}`)
	reVar   = regexp.MustCompile(`\$\{VAR\:([^}]+)\}`)
	reUUID  = regexp.MustCompile(`\$\{UUID\}`)
	reIP    = regexp.MustCompile(`\$\{IP\}`)
	reIPNet = regexp.MustCompile(`\$\{IP\:([^}]+)\}`)
	reHash  = regexp.MustCompile(`\$\{HASH\:(\d+)\}`)
	reBatch = regexp.MustCompile(`\$\{BATCH\}`)
	reIter  = regexp.MustCompile(`\$\{ITER\}`)
	reLeft  = regexp.MustCompile(`\$\{[^}]*\}?`)
)

// Tokens lists the supported tokens, for error messages.
const Tokens = "${SEQ} ${BATCH} ${ITER} ${RND:N} ${RANDOM:N} ${DATE:layout} ${ACTOR} ${VAR:name} ${UUID} ${IP} ${IP:cidr} ${HASH:N}"

// literal stands in for an escaped "$${" while the rules run. It cannot occur
// in YAML text, which may not contain raw NUL bytes.
const literal = "\x00fsagen-literal\x00"

// Apply substitutes every supported token in s.
//
// Random tokens are keyed by kind and position within the field (see
// Context), so neither the order the rules run in nor the other tokens in
// the string affect their values. ${RND} and ${RANDOM} are one kind.
func Apply(s string, ctx Context) (string, error) {
	if s == "" {
		return s, nil
	}
	var errs []string
	out := strings.ReplaceAll(s, "$${", literal)

	nRnd := 0
	out = reRnd.ReplaceAllStringFunc(out, func(m string) string {
		n, err := strconv.Atoi(reRnd.FindStringSubmatch(m)[2])
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Sprintf("%s: length must be at least 1", m))
			return ""
		}
		nRnd++
		return ctx.draw("RND", nRnd-1).Text(n)
	})

	out = reSeq.ReplaceAllString(out, strconv.Itoa(ctx.Seq))
	out = reBatch.ReplaceAllString(out, strconv.Itoa(ctx.BatchIdx))
	out = reIter.ReplaceAllString(out, strconv.Itoa(ctx.Iteration))

	out = reDate.ReplaceAllStringFunc(out, func(m string) string {
		if ctx.Timestamp.IsZero() {
			errs = append(errs, fmt.Sprintf("%s has no reference time (in a manifest it is the operation's mtime, else the manifest's start)", m))
			return ""
		}
		return ctx.Timestamp.Format(reDate.FindStringSubmatch(m)[1])
	})

	if ctx.Actor != "" {
		out = reActor.ReplaceAllString(out, ctx.Actor)
	}

	out = reVar.ReplaceAllStringFunc(out, func(m string) string {
		name := reVar.FindStringSubmatch(m)[1]
		if val, ok := ctx.Variables[name]; ok {
			return val
		}
		errs = append(errs, fmt.Sprintf("undefined variable %q%s", name, knownVars(ctx.Variables)))
		return ""
	})

	// A well-formed v4 UUID, not the obviously synthetic zero-padded shape the
	// playbook renderer used to emit.
	nUUID := 0
	out = reUUID.ReplaceAllStringFunc(out, func(string) string {
		nUUID++
		return ctx.draw("UUID", nUUID-1).UUID()
	})

	// ${IP:10.0.0.0/8} draws an address inside the block from the operation's
	// own stream; bare ${IP} keeps the old walk through 192.168.x.y.
	nIP := 0
	out = reIPNet.ReplaceAllStringFunc(out, func(m string) string {
		nIP++
		addr, err := addressIn(reIPNet.FindStringSubmatch(m)[1], ctx.draw("IP", nIP-1))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", m, err))
			return ""
		}
		return addr
	})
	out = reIP.ReplaceAllString(out, fmt.Sprintf("192.168.%d.%d", (ctx.Seq/256)%256, ctx.Seq%256))

	// Lowercase hex: a "SHA256" containing Z or = fails the sniff test.
	nHash := 0
	out = reHash.ReplaceAllStringFunc(out, func(m string) string {
		n, err := strconv.Atoi(reHash.FindStringSubmatch(m)[1])
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Sprintf("%s: length must be at least 1", m))
			return ""
		}
		nHash++
		return ctx.draw("HASH", nHash-1).Hex(n)
	})

	for _, m := range reLeft.FindAllString(out, -1) {
		switch {
		case m == "${ACTOR}":
			errs = append(errs, "${ACTOR} has no value here (it is only defined in playbooks)")
		case !strings.HasSuffix(m, "}"):
			errs = append(errs, fmt.Sprintf("unterminated token %q", m))
		default:
			errs = append(errs, fmt.Sprintf("unknown token %s (supported: %s; write $${ for a literal ${)", m, Tokens))
		}
	}
	if len(errs) > 0 {
		return "", fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return strings.ReplaceAll(out, literal, "${"), nil
}

// addressIn returns an address inside the CIDR block, drawn from s. For an
// IPv4 block big enough to have them, the network and broadcast addresses are
// left out: no host has one, so a corpus should not either.
func addressIn(cidr string, s *prng.Stream) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return "", fmt.Errorf("%q is not a CIDR block (for example 10.0.0.0/8)", cidr)
	}
	p = p.Masked()
	base := p.Addr()
	host := base.BitLen() - p.Bits()
	if host == 0 {
		return base.String(), nil
	}
	// An IPv6 block can hold more addresses than fit in a 64-bit draw, so
	// only the low bits of the block are used.
	if host > 62 {
		host = 62
	}
	size := int(1) << host
	n := s.IntN(size)
	if base.Is4() && host >= 2 {
		n = 1 + s.IntN(size-2)
	}
	b := base.AsSlice()
	for i := len(b) - 1; i >= 0 && n > 0; i-- {
		sum := int(b[i]) + n&0xff
		b[i] = byte(sum)
		n = n>>8 + sum>>8
	}
	addr, ok := netip.AddrFromSlice(b)
	if !ok {
		return "", fmt.Errorf("%q produced no address", cidr)
	}
	return addr.Unmap().String(), nil
}

func knownVars(vars map[string]string) string {
	if len(vars) == 0 {
		return " (no variables are defined)"
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	return " (defined: " + strings.Join(names, ", ") + ")"
}

// MergeVariables layers maps left to right; later maps win.
func MergeVariables(layers ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, layer := range layers {
		for k, v := range layer {
			result[k] = v
		}
	}
	return result
}

// ParseVarAssignment splits a "key=value" CLI assignment.
func ParseVarAssignment(s string) (string, string, error) {
	k, v, ok := strings.Cut(s, "=")
	k = strings.TrimSpace(k)
	if !ok || k == "" {
		return "", "", fmt.Errorf("invalid variable %q (expected key=value)", s)
	}
	return k, v, nil
}

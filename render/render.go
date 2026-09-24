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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/util"
)

// Context supplies the values that tokens resolve against. Manifests leave
// Actor, BatchIdx and Iteration at their zero values.
type Context struct {
	Seq       int
	BatchIdx  int
	Iteration int
	Actor     string
	Timestamp time.Time
	Variables map[string]string
}

var (
	reRnd   = regexp.MustCompile(`\$\{(RND|RANDOM)\:(\d+)\}`)
	reSeq   = regexp.MustCompile(`\$\{SEQ\}`)
	reDate  = regexp.MustCompile(`\$\{DATE\:([^}]+)\}`)
	reActor = regexp.MustCompile(`\$\{ACTOR\}`)
	reVar   = regexp.MustCompile(`\$\{VAR\:([^}]+)\}`)
	reUUID  = regexp.MustCompile(`\$\{UUID\}`)
	reIP    = regexp.MustCompile(`\$\{IP\}`)
	reHash  = regexp.MustCompile(`\$\{HASH\:(\d+)\}`)
	reBatch = regexp.MustCompile(`\$\{BATCH\}`)
	reIter  = regexp.MustCompile(`\$\{ITER\}`)
	reLeft  = regexp.MustCompile(`\$\{[^}]*\}?`)
)

// Tokens lists the supported tokens, for error messages.
const Tokens = "${SEQ} ${BATCH} ${ITER} ${RND:N} ${RANDOM:N} ${DATE:layout} ${ACTOR} ${VAR:name} ${UUID} ${IP} ${HASH:N}"

// literal stands in for an escaped "$${" while the rules run. It cannot occur
// in YAML text, which may not contain raw NUL bytes.
const literal = "\x00fsagen-literal\x00"

// Apply substitutes every supported token in s.
//
// The rules run in a fixed order (random strings, counters, dates, actor,
// variables, UUIDs, IPs, hashes), which fixes the order of PRNG draws and so
// the bytes a given seed produces. Do not reorder them without bumping the
// generator version.
func Apply(s string, ctx Context) (string, error) {
	if s == "" {
		return s, nil
	}
	var errs []string
	out := strings.ReplaceAll(s, "$${", literal)

	out = reRnd.ReplaceAllStringFunc(out, func(m string) string {
		n, err := strconv.Atoi(reRnd.FindStringSubmatch(m)[2])
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Sprintf("%s: length must be at least 1", m))
			return ""
		}
		return util.GetRandomString(n)
	})

	out = reSeq.ReplaceAllString(out, strconv.Itoa(ctx.Seq))
	out = reBatch.ReplaceAllString(out, strconv.Itoa(ctx.BatchIdx))
	out = reIter.ReplaceAllString(out, strconv.Itoa(ctx.Iteration))

	out = reDate.ReplaceAllStringFunc(out, func(m string) string {
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
	out = reUUID.ReplaceAllStringFunc(out, func(string) string {
		return util.GetRandomUUID()
	})

	out = reIP.ReplaceAllString(out, fmt.Sprintf("192.168.%d.%d", (ctx.Seq/256)%256, ctx.Seq%256))

	// Lowercase hex: a "SHA256" containing Z or = fails the sniff test.
	out = reHash.ReplaceAllStringFunc(out, func(m string) string {
		n, err := strconv.Atoi(reHash.FindStringSubmatch(m)[1])
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Sprintf("%s: length must be at least 1", m))
			return ""
		}
		return util.GetRandomHex(n)
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

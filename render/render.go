// Package render implements the ${...} token substitution shared by manifests
// and playbooks. Both modes previously carried their own copy of this logic and
// had drifted apart: manifests understood three tokens, playbooks eleven.
package render

import (
	"fmt"
	"fsagen/util"
	"regexp"
	"strconv"
	"strings"
	"time"
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
)

// Apply substitutes every supported token in s.
//
// Supported: ${SEQ} ${BATCH} ${ITER} ${RND:N} ${RANDOM:N} ${DATE:layout}
// ${ACTOR} ${VAR:name} ${UUID} ${IP} ${HASH:N}
//
// An unknown ${VAR:name} is left verbatim rather than blanked, so a typo shows
// up in the output instead of silently producing an empty field.
func Apply(s string, ctx Context) string {
	if s == "" {
		return s
	}
	out := s

	out = reRnd.ReplaceAllStringFunc(out, func(m string) string {
		parts := reRnd.FindStringSubmatch(m)
		if len(parts) != 3 {
			return m
		}
		n, err := strconv.Atoi(parts[2])
		if err != nil || n <= 0 {
			n = 8
		}
		return util.GetRandomString(n)
	})

	out = reSeq.ReplaceAllString(out, strconv.Itoa(ctx.Seq))
	out = reBatch.ReplaceAllString(out, strconv.Itoa(ctx.BatchIdx))
	out = reIter.ReplaceAllString(out, strconv.Itoa(ctx.Iteration))

	out = reDate.ReplaceAllStringFunc(out, func(m string) string {
		parts := reDate.FindStringSubmatch(m)
		if len(parts) != 2 {
			return m
		}
		return ctx.Timestamp.Format(parts[1])
	})

	if ctx.Actor != "" {
		out = reActor.ReplaceAllString(out, ctx.Actor)
	}

	out = reVar.ReplaceAllStringFunc(out, func(m string) string {
		parts := reVar.FindStringSubmatch(m)
		if len(parts) != 2 {
			return m
		}
		if val, ok := ctx.Variables[parts[1]]; ok {
			return val
		}
		return m
	})

	// A well-formed v4 UUID, not the obviously synthetic zero-padded shape the
	// playbook renderer used to emit.
	out = reUUID.ReplaceAllStringFunc(out, func(string) string {
		return util.GetRandomUUID()
	})

	out = reIP.ReplaceAllString(out, fmt.Sprintf("192.168.%d.%d", (ctx.Seq/256)%256, ctx.Seq%256))

	// Lowercase hex: a "SHA256" containing Z or = fails the sniff test.
	out = reHash.ReplaceAllStringFunc(out, func(m string) string {
		parts := reHash.FindStringSubmatch(m)
		if len(parts) != 2 {
			return m
		}
		n, err := strconv.Atoi(parts[1])
		if err != nil || n <= 0 {
			n = 32
		}
		return util.GetRandomHex(n)
	})

	return out
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

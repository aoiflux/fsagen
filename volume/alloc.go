package volume

import (
	"errors"
	"fmt"
	"math/bits"
)

// The allocation policies.
const (
	// NextFit searches on from where the last allocation ended, as Windows'
	// FAT and NTFS drivers do: freed space is reused only once the volume
	// wraps round.
	NextFit = "next-fit"
	// FirstFit searches from the lowest unit every time, so freed space is
	// reused at once.
	FirstFit = "first-fit"
)

// Policies lists the allocation policies.
var Policies = []string{NextFit, FirstFit}

// ErrFull is returned when the volume has too few free units left.
var ErrFull = errors.New("the volume is full")

// Run is Len units from Start.
type Run struct{ Start, Len int }

// Allocator hands out units (clusters or blocks) numbered first to
// first+n-1. It prefers one contiguous run, and fragments a request only
// when no run is long enough.
type Allocator struct {
	first, n int
	used     []uint64
	free     int
	hint     int
	firstFit bool
}

// NewAllocator manages n units numbered from first, all free.
func NewAllocator(first, n int, policy string) (*Allocator, error) {
	if policy != NextFit && policy != FirstFit && policy != "" {
		return nil, fmt.Errorf("unknown allocation policy %q", policy)
	}
	return &Allocator{first: first, n: n, used: make([]uint64, (n+63)/64), free: n, hint: first, firstFit: policy == FirstFit}, nil
}

// Free is the number of free units.
func (a *Allocator) Free() int { return a.free }

// Hint is the unit the next search starts at.
func (a *Allocator) Hint() int { return a.hint }

func (a *Allocator) isUsed(u int) bool {
	i := u - a.first
	return a.used[i/64]&(1<<(i%64)) != 0
}

func (a *Allocator) set(u int, on bool) {
	i := u - a.first
	if on {
		a.used[i/64] |= 1 << (i % 64)
	} else {
		a.used[i/64] &^= 1 << (i % 64)
	}
}

// Mark takes units out of use without allocating them through a search,
// for structures a format puts at fixed places.
func (a *Allocator) Mark(r Run) {
	for u := r.Start; u < r.Start+r.Len; u++ {
		if !a.isUsed(u) {
			a.set(u, true)
			a.free--
		}
	}
}

// nextFree is the first free unit at or after u, or -1.
func (a *Allocator) nextFree(u int) int {
	for i := u - a.first; i < a.n; {
		w := a.used[i/64] >> (i % 64)
		if w == ^uint64(0)>>(i%64) {
			i = (i/64 + 1) * 64
			continue
		}
		i += bits.TrailingZeros64(^w)
		if i >= a.n {
			break
		}
		return a.first + i
	}
	return -1
}

// runAt is the length of the free run starting at u, up to max.
func (a *Allocator) runAt(u, max int) int {
	n := 0
	for u+n < a.first+a.n && n < max && !a.isUsed(u+n) {
		n++
	}
	return n
}

// Alloc allocates count units. near, when not negative, is where the search
// starts (just after a file's last unit, to extend it in place); otherwise
// it starts at the policy's place. One run of count free units is taken if
// there is one; else free units in order from the start, wrapping round.
func (a *Allocator) Alloc(count, near int) ([]Run, error) {
	if count == 0 {
		return nil, nil
	}
	if count > a.free {
		return nil, fmt.Errorf("%w: %d unit(s) wanted, %d free", ErrFull, count, a.free)
	}
	start := a.hint
	if a.firstFit {
		start = a.first
	}
	if near >= a.first && near < a.first+a.n {
		start = near
	}
	if u := a.findRun(start, count); u >= 0 {
		return a.take([]Run{{u, count}}), nil
	}
	var runs []Run
	for u, left := start, count; left > 0; {
		f := a.nextFree(u)
		if f < 0 {
			f = a.nextFree(a.first)
		}
		k := a.runAt(f, left)
		runs = append(runs, Run{f, k})
		a.take([]Run{{f, k}})
		left -= k
		u = f + k
		if u >= a.first+a.n {
			u = a.first
		}
	}
	return runs, nil
}

// findRun finds count free units in a row from start on, then from the
// first unit, or returns -1.
func (a *Allocator) findRun(start, count int) int {
	for _, from := range []int{start, a.first} {
		for u := a.nextFree(from); u >= 0; {
			k := a.runAt(u, count)
			if k == count {
				return u
			}
			u = a.nextFree(u + k)
		}
	}
	return -1
}

func (a *Allocator) take(runs []Run) []Run {
	for _, r := range runs {
		a.Mark(r)
		a.hint = r.Start + r.Len
	}
	if a.hint >= a.first+a.n {
		a.hint = a.first
	}
	return runs
}

// Release frees units.
func (a *Allocator) Release(units []int) {
	for _, u := range units {
		if a.isUsed(u) {
			a.set(u, false)
			a.free++
		}
	}
}

// Units lists the units of runs in order.
func Units(runs []Run) []int {
	var out []int
	for _, r := range runs {
		for u := r.Start; u < r.Start+r.Len; u++ {
			out = append(out, u)
		}
	}
	return out
}
